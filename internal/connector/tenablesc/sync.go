package tenablesc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// CommandTypeSync is the platform command that runs a pull.
const CommandTypeSync = "connector_sync"

// Sync modes and include kinds (the platform's command payload).
const (
	ModeIncremental = "incremental"
	ModeFull        = "full"

	IncludeHosts     = "hosts"
	IncludeVulns     = "vulns"
	IncludeMitigated = "mitigated"
	IncludePlugins   = "plugins"
)

const (
	maxPayloadBytes          = 64 << 10
	maxFindingsPerReport     = 2000
	defaultFullMitigatedDays = 30
	maxWindowDays            = 365
	defaultMinSeverity       = 1
	maxPluginLookups         = 5000
	sortField                = "pluginID"
	sortDir                  = "ASC"
)

// ErrRefused marks a command the connector will not run (the platform asked
// for something the sensor owner did not allow, or sent a bad payload).
var ErrRefused = errors.New("tenable.sc connector refused the job")

// Pusher sends a report to the platform. The sensor passes its API client.
type Pusher interface {
	PushFindings(ctx context.Context, report *ctis.Report) (*core.PushResult, error)
}

// SyncPayload is the connector_sync command payload.
type SyncPayload struct {
	Scanner           string   `json:"scanner"`
	Instance          string   `json:"instance"`
	IntegrationID     string   `json:"integration_id,omitempty"`
	Mode              string   `json:"mode,omitempty"`
	WindowDays        int      `json:"window_days,omitempty"`
	FullMitigatedDays int      `json:"full_mitigated_days,omitempty"`
	Include           []string `json:"include,omitempty"`
	MinSeverity       *int     `json:"min_severity,omitempty"`
	Repositories      []int    `json:"repositories,omitempty"`
}

// SyncExecutor runs connector_sync commands.
type SyncExecutor struct {
	Config *Config
	Pusher Pusher
	// Logf, when set, receives progress lines (never keys).
	Logf func(format string, args ...any)

	now       func() time.Time
	newClient func(*Instance) (*Client, error)
}

// NewSyncExecutor returns the executor for cfg.
func NewSyncExecutor(cfg *Config, p Pusher) *SyncExecutor {
	return &SyncExecutor{Config: cfg, Pusher: p}
}

type syncJob struct {
	inst         *Instance
	mode         string
	windowDays   int
	mitDays      int
	include      map[string]bool
	minSeverity  int
	repositories []int
}

// Execute runs one sync.
func (e *SyncExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	start := e.clock()
	if cmd == nil || cmd.Type != CommandTypeSync {
		return nil, fmt.Errorf("%w: not a %s command", ErrRefused, CommandTypeSync)
	}
	job, err := e.admit(cmd.Payload)
	if err != nil {
		return nil, err
	}
	newClient := e.newClient
	if newClient == nil {
		newClient = NewClient
	}
	client, err := newClient(job.inst)
	if err != nil {
		return nil, err
	}
	run := &syncRun{
		e: e, job: job, client: client, cmdID: cmd.ID,
		ctx:     core.WithCommandID(ctx, cmd.ID),
		mapper:  &mapper{now: start, plugins: map[string]*plugin{}},
		emitted: map[string]bool{},
		ipSeen:  map[string]*hostSeen{},
	}
	if err := run.execute(); err != nil {
		return nil, fmt.Errorf("tenable.sc sync of %q: %w", job.inst.Name, err)
	}
	dur := e.clock().Sub(start)
	return &core.CommandExecutionResult{
		DurationMs:    dur.Milliseconds(),
		FindingsCount: run.counts.open + run.counts.mitigated,
		Metadata:      run.metadata(dur),
	}, nil
}

func (e *SyncExecutor) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

func (e *SyncExecutor) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

// admit checks the payload against the connector config: the sensor owner's
// limits, which the platform cannot change.
func (e *SyncExecutor) admit(raw json.RawMessage) (*syncJob, error) {
	if len(raw) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: payload larger than %d bytes", ErrRefused, maxPayloadBytes)
	}
	var p SyncPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrRefused, err)
	}
	if p.Scanner != ToolName {
		return nil, fmt.Errorf("%w: scanner must be %q", ErrRefused, ToolName)
	}
	inst := e.Config.Instance(p.Instance)
	if inst == nil {
		return nil, fmt.Errorf("%w: no Tenable.sc instance %q is configured on this sensor", ErrRefused, sanitizeText(p.Instance, 64))
	}
	if !inst.Allow.Operations[OperationSync] {
		return nil, fmt.Errorf("%w: the sensor owner does not allow sync on instance %q", ErrRefused, inst.Name)
	}
	job := &syncJob{inst: inst, include: map[string]bool{}}
	switch p.Mode {
	case "", ModeIncremental:
		job.mode = ModeIncremental
		if p.WindowDays < 1 || p.WindowDays > maxWindowDays {
			return nil, fmt.Errorf("%w: window_days must be 1..%d for an incremental sync", ErrRefused, maxWindowDays)
		}
		job.windowDays = p.WindowDays
	case ModeFull:
		job.mode = ModeFull
	default:
		return nil, fmt.Errorf("%w: unknown mode %q", ErrRefused, sanitizeText(p.Mode, 32))
	}
	job.mitDays = defaultFullMitigatedDays
	if p.FullMitigatedDays != 0 {
		if p.FullMitigatedDays < 1 || p.FullMitigatedDays > maxWindowDays {
			return nil, fmt.Errorf("%w: full_mitigated_days must be 1..%d", ErrRefused, maxWindowDays)
		}
		job.mitDays = p.FullMitigatedDays
	}
	if len(p.Include) == 0 {
		p.Include = []string{IncludeHosts, IncludeVulns, IncludeMitigated, IncludePlugins}
	}
	for _, k := range p.Include {
		switch k {
		case IncludeHosts, IncludeVulns, IncludeMitigated, IncludePlugins:
			job.include[k] = true
		default:
			return nil, fmt.Errorf("%w: unknown include %q", ErrRefused, sanitizeText(k, 32))
		}
	}
	job.minSeverity = defaultMinSeverity
	if p.MinSeverity != nil {
		if *p.MinSeverity < 0 || *p.MinSeverity > 4 {
			return nil, fmt.Errorf("%w: min_severity must be 0..4", ErrRefused)
		}
		job.minSeverity = *p.MinSeverity
	}
	if len(p.Repositories) == 0 {
		job.repositories = slices.Clone(inst.Allow.Repositories)
	} else {
		for _, id := range p.Repositories {
			if inst.Allow.AllowsRepository(id) && !slices.Contains(job.repositories, id) {
				job.repositories = append(job.repositories, id)
			}
		}
		if len(job.repositories) == 0 {
			return nil, fmt.Errorf("%w: none of the requested repositories is allowed by the sensor owner", ErrRefused)
		}
	}
	slices.Sort(job.repositories)
	return job, nil
}

type syncCounts struct {
	hosts, open, mitigated, plugins, reports int
	skippedNoAsset, skippedBadRow            int
	pluginErrors, pluginsSkipped             int
	ipCollisions                             int
}

type syncRun struct {
	e      *SyncExecutor
	job    *syncJob
	client *Client
	cmdID  string
	ctx    context.Context
	mapper *mapper

	version string
	license *License

	records int // rows read so far, all queries
	chunk   int
	pending []ctis.Finding
	assets  map[string]ctis.Asset // assets of pending findings
	emitted map[string]bool       // asset ids pushed in any report
	ipSeen  map[string]*hostSeen  // ip -> first repository and host uuid

	newestSeen, newestMitigated time.Time
	counts                      syncCounts
	pluginLookups               int
}

func (r *syncRun) execute() error {
	sys, err := r.client.System(r.ctx)
	if err != nil {
		return err
	}
	r.version = sys.Version
	if lic, err := r.client.Status(r.ctx); err == nil {
		r.license = &lic
	} else if errors.Is(err, ErrCredentialsRejected) || r.ctx.Err() != nil {
		return err
	} else {
		r.e.logf("tenable.sc %s: license status unavailable: %v", r.job.inst.Name, err)
	}

	if r.job.include[IncludeVulns] {
		if err := r.query(r.vulnQuery("cumulative"), stateOpen); err != nil {
			return err
		}
	}
	if r.job.include[IncludeMitigated] {
		if err := r.query(r.vulnQuery("patched"), stateMitigated); err != nil {
			return err
		}
	}
	if err := r.flush(); err != nil {
		return err
	}
	if r.job.include[IncludeHosts] {
		if err := r.hosts(); err != nil {
			return err
		}
	}
	return r.flush()
}

func (r *syncRun) baseFilters(withSeverity bool) []Filter {
	repos := make([]map[string]string, 0, len(r.job.repositories))
	for _, id := range r.job.repositories {
		repos = append(repos, map[string]string{"id": strconv.Itoa(id)})
	}
	f := []Filter{{FilterName: "repository", Operator: "=", Value: repos}}
	if withSeverity {
		sev := make([]string, 0, 5)
		for s := r.job.minSeverity; s <= 4; s++ {
			sev = append(sev, strconv.Itoa(s))
		}
		f = append(f, Filter{FilterName: "severity", Operator: "=", Value: strings.Join(sev, ",")})
	}
	return f
}

func (r *syncRun) vulnQuery(sourceType string) Query {
	f := r.baseFilters(true)
	switch {
	case sourceType == "patched" && r.job.mode == ModeFull:
		f = append(f, Filter{FilterName: "lastMitigated", Operator: "=", Value: fmt.Sprintf("0:%d", r.job.mitDays)})
	case sourceType == "patched":
		f = append(f, Filter{FilterName: "lastMitigated", Operator: "=", Value: fmt.Sprintf("0:%d", r.job.windowDays)})
	case r.job.mode == ModeIncremental:
		f = append(f, Filter{FilterName: "lastSeen", Operator: "=", Value: fmt.Sprintf("0:%d", r.job.windowDays)})
	}
	return Query{Tool: "vulndetails", SourceType: sourceType, Filters: f, SortField: sortField, SortDir: sortDir}
}

// pages runs q page by page. The first page's total is checked against the
// record budget before any row of the query is used, so a query that would
// exceed it pushes nothing.
func (r *syncRun) pages(q Query, each func(rows []json.RawMessage) error) error {
	size := r.job.inst.Limits.PageSize
	budget := r.job.inst.Limits.MaxRecords - r.records
	offset, total := 0, -1
	maxPages := r.job.inst.Limits.MaxRecords/size + 2
	for page := 0; ; page++ {
		if page > maxPages {
			return fmt.Errorf("%w: paging did not end", ErrTooManyRecords)
		}
		p, err := r.client.Analysis(r.ctx, q, offset, size)
		if err != nil {
			return err
		}
		if total < 0 {
			total = p.Total
			if total > budget {
				return fmt.Errorf("%w: %d %s records, %d left of %d", ErrTooManyRecords, total, q.SourceType, max(budget, 0), r.job.inst.Limits.MaxRecords)
			}
		}
		if len(p.Results) == 0 {
			return nil
		}
		if r.records+len(p.Results) > r.job.inst.Limits.MaxRecords {
			return ErrTooManyRecords
		}
		r.records += len(p.Results)
		if err := each(p.Results); err != nil {
			return err
		}
		offset += len(p.Results)
		if offset >= total {
			return nil
		}
	}
}

func (r *syncRun) query(q Query, state string) error {
	return r.pages(q, func(raw []json.RawMessage) error {
		rows := make([]*vulnRow, 0, len(raw))
		for _, b := range raw {
			var row vulnRow
			if err := json.Unmarshal(b, &row); err != nil {
				return fmt.Errorf("tenable.sc returned an unreadable row: %w", err)
			}
			rows = append(rows, &row)
		}
		if r.job.include[IncludePlugins] {
			if err := r.enrich(rows); err != nil {
				return err
			}
		}
		for _, row := range rows {
			if sanitizeIdentifier(string(row.PluginID)) == "" {
				r.counts.skippedBadRow++
				continue
			}
			h, ok := r.mapper.host(row)
			if !ok {
				r.counts.skippedNoAsset++
				continue
			}
			r.noteHost(h)
			f := r.mapper.finding(row, h, state)
			if state == stateMitigated {
				r.counts.mitigated++
				r.newestMitigated = later(r.newestMitigated, r.mapper.timestamp(row.LastMitigated))
			} else {
				r.counts.open++
				r.newestSeen = later(r.newestSeen, r.mapper.timestamp(row.LastSeen))
			}
			if err := r.add(f, h.asset); err != nil {
				return err
			}
		}
		return nil
	})
}

// hosts adds the hosts with no finding at or above min_severity (sumip).
func (r *syncRun) hosts() error {
	f := r.baseFilters(false)
	if r.job.mode == ModeIncremental {
		f = append(f, Filter{FilterName: "lastSeen", Operator: "=", Value: fmt.Sprintf("0:%d", r.job.windowDays)})
	}
	q := Query{Tool: "sumip", SourceType: "cumulative", Filters: f, SortField: "ip", SortDir: sortDir}
	return r.pages(q, func(raw []json.RawMessage) error {
		for _, b := range raw {
			var row vulnRow
			if err := json.Unmarshal(b, &row); err != nil {
				return fmt.Errorf("tenable.sc returned an unreadable host row: %w", err)
			}
			h, ok := r.mapper.host(&row)
			if !ok {
				r.counts.skippedNoAsset++
				continue
			}
			if r.emitted[h.assetID] {
				continue
			}
			if _, queued := r.assets[h.assetID]; queued {
				continue
			}
			r.noteHost(h)
			if r.assets == nil {
				r.assets = map[string]ctis.Asset{}
			}
			r.assets[h.assetID] = h.asset
			if len(r.assets) >= maxFindingsPerReport {
				if err := r.flush(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// noteHost counts hosts, and IPs that two repositories report for two
// different machines (overlapping address spaces, RFC-047 §7.1).
func (r *syncRun) noteHost(h hostKey) {
	if h.ip == "" {
		return
	}
	prev, seen := r.ipSeen[h.ip]
	if !seen {
		r.ipSeen[h.ip] = &hostSeen{repo: h.repo, hostID: h.hostID}
		r.counts.hosts++
		return
	}
	if !prev.collided && prev.repo != h.repo && prev.hostID != "" && h.hostID != "" && prev.hostID != h.hostID {
		prev.collided = true
		r.counts.ipCollisions++
	}
}

type hostSeen struct {
	repo, hostID string
	collided     bool
}

func (r *syncRun) enrich(rows []*vulnRow) error {
	for _, row := range rows {
		id := sanitizeIdentifier(string(row.PluginID))
		if id == "" {
			continue
		}
		if _, done := r.mapper.plugins[id]; done {
			continue
		}
		if r.pluginLookups >= maxPluginLookups {
			r.mapper.plugins[id] = nil
			r.counts.pluginsSkipped++
			continue
		}
		r.pluginLookups++
		p, err := r.client.Plugin(r.ctx, id)
		if err != nil {
			if errors.Is(err, ErrCredentialsRejected) || r.ctx.Err() != nil {
				return err
			}
			r.mapper.plugins[id] = nil
			r.counts.pluginErrors++
			continue
		}
		r.mapper.plugins[id] = p
		r.counts.plugins++
	}
	return nil
}

func (r *syncRun) add(f ctis.Finding, a ctis.Asset) error {
	if r.assets == nil {
		r.assets = map[string]ctis.Asset{}
	}
	if _, ok := r.assets[a.ID]; !ok {
		r.assets[a.ID] = a
	}
	r.pending = append(r.pending, f)
	if len(r.pending) >= maxFindingsPerReport {
		return r.flush()
	}
	return nil
}

// flush pushes the pending findings and their assets as one report bound
// to the command.
func (r *syncRun) flush() error {
	if len(r.pending) == 0 && len(r.assets) == 0 {
		return nil
	}
	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID:           fmt.Sprintf("%s-%d", r.cmdID, r.chunk),
			Timestamp:    r.e.clock(),
			SourceType:   "scanner",
			CoverageType: "incremental",
		},
		Tool: &ctis.Tool{Name: ToolName, Vendor: toolVendor, Version: r.version},
	}
	ids := make([]string, 0, len(r.assets))
	for id := range r.assets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		report.Assets = append(report.Assets, r.assets[id])
		r.emitted[id] = true
	}
	report.Findings = r.pending
	res, err := r.e.Pusher.PushFindings(r.ctx, report)
	if err != nil {
		return fmt.Errorf("push report %d: %w", r.chunk, err)
	}
	if res != nil && !res.Success && !res.Queued {
		return fmt.Errorf("push report %d: the platform did not accept it: %s", r.chunk, sanitizeText(res.Message, maxErrorMsgBytes))
	}
	r.counts.reports++
	r.chunk++
	r.pending = nil
	r.assets = nil
	return nil
}

func (r *syncRun) metadata(dur time.Duration) map[string]any {
	md := map[string]any{
		"connector":       ToolName,
		"instance":        r.job.inst.Name,
		"mode":            r.job.mode,
		"tenable_version": r.version,
		"repositories":    r.job.repositories,
		"counts": map[string]int{
			"hosts":     r.counts.hosts,
			"open":      r.counts.open,
			"mitigated": r.counts.mitigated,
			"plugins":   r.counts.plugins,
			"reports":   r.counts.reports,
			"records":   r.records,
		},
		"skipped": map[string]int{
			"no_asset":        r.counts.skippedNoAsset,
			"bad_row":         r.counts.skippedBadRow,
			"plugin_errors":   r.counts.pluginErrors,
			"plugins_skipped": r.counts.pluginsSkipped,
		},
		// Flat counters the platform reads to update the integration.
		"hosts":         r.counts.hosts,
		"open":          r.counts.open,
		"mitigated":     r.counts.mitigated,
		"plugins":       r.counts.plugins,
		"ip_collisions": r.counts.ipCollisions,
		"truncated":     false,
		"duration_ms":   dur.Milliseconds(),
	}
	if r.job.mode == ModeIncremental {
		md["window_days"] = r.job.windowDays
	}
	if r.license != nil {
		md["licensed_ips"] = r.license.LicensedIPs
		md["active_ips"] = r.license.ActiveIPs
		if r.license.Status != "" {
			md["license_status"] = r.license.Status
		}
	}
	if !r.newestSeen.IsZero() {
		md["newest_last_seen"] = r.newestSeen.Format(time.RFC3339)
	}
	if !r.newestMitigated.IsZero() {
		md["newest_last_mitigated"] = r.newestMitigated.Format(time.RFC3339)
	}
	return md
}

func later(cur time.Time, t *time.Time) time.Time {
	if t != nil && t.After(cur) {
		return *t
	}
	return cur
}
