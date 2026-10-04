package tenablesc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// CommandTypeScan is the platform command that launches one Tenable.sc scan.
const CommandTypeScan = "connector_scan"

// Scan settings.
const (
	defaultPollInterval = 30 * time.Second
	importGrace         = 30 * time.Minute
	cleanupTimeout      = 30 * time.Second
	minIPv4PrefixBits   = 16
	minIPv6PrefixBits   = 120
	maxHostnameLen      = 253
)

// Coverage values of a scan report.
const (
	CoverageFull    = "full"
	CoveragePartial = "partial"
)

// ScanPayload is the connector_scan command payload. The bookkeeping keys
// the platform adds for its own scan runs are accepted and ignored.
type ScanPayload struct {
	Scanner        string   `json:"scanner"`
	Instance       string   `json:"instance"`
	IntegrationID  string   `json:"integration_id,omitempty"`
	Targets        []string `json:"targets"`
	PolicyID       int      `json:"policy_id"`
	RepositoryID   int      `json:"repository_id"`
	ZoneID         int      `json:"zone_id,omitempty"`
	MaxScanSeconds int      `json:"max_scan_seconds,omitempty"`
	MinSeverity    *int     `json:"min_severity,omitempty"`

	// Platform bookkeeping, ignored here.
	RunID         string `json:"run_id,omitempty"`
	ScanID        string `json:"scan_id,omitempty"`
	PipelineRunID string `json:"pipeline_run_id,omitempty"`
	StepKey       string `json:"step_key,omitempty"`
	StepRunID     string `json:"step_run_id,omitempty"`
}

// TargetChecker is the sensor-local policy's target check
// (core.LocalPolicy.CheckTarget).
type TargetChecker interface {
	CheckTarget(ctx context.Context, target string) error
}

// ScanExecutor runs connector_scan commands.
type ScanExecutor struct {
	Config *Config
	Pusher Pusher
	// Policy is the sensor-local policy; nil when none is installed.
	Policy TargetChecker
	// Logf, when set, receives progress lines (never keys).
	Logf func(format string, args ...any)

	now          func() time.Time
	newClient    func(*Instance) (*Client, error)
	pollInterval time.Duration
	sleep        func(ctx context.Context, d time.Duration) error
}

// NewScanExecutor returns the executor for cfg.
func NewScanExecutor(cfg *Config, p Pusher, policy TargetChecker) *ScanExecutor {
	return &ScanExecutor{Config: cfg, Pusher: p, Policy: policy}
}

// AllowsScans reports whether any configured instance allows connector_scan.
func (c *Config) AllowsScans() bool {
	if c == nil {
		return false
	}
	for _, in := range c.Instances {
		if in != nil && in.Allow.Operations[OperationScan] {
			return true
		}
	}
	return false
}

type scanJob struct {
	inst        *Instance
	targets     []string
	addresses   int64
	policyID    int
	repoID      int
	zoneID      int
	maxSeconds  int
	minSeverity int
}

// Execute runs one scan: admission, create, launch, poll, pull, delete.
func (e *ScanExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	start := e.clock()
	if cmd == nil || cmd.Type != CommandTypeScan {
		return nil, fmt.Errorf("%w: not a %s command", ErrRefused, CommandTypeScan)
	}
	job, err := e.admit(ctx, cmd.Payload)
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
	run := &scanRun{e: e, job: job, client: client, cmdID: cmd.ID, ctx: core.WithCommandID(ctx, cmd.ID)}
	md, err := run.execute()
	if err != nil {
		return nil, fmt.Errorf("tenable.sc scan on %q: %w", job.inst.Name, err)
	}
	dur := e.clock().Sub(start)
	md["duration_ms"] = dur.Milliseconds()
	return &core.CommandExecutionResult{DurationMs: dur.Milliseconds(), FindingsCount: run.open, Metadata: md}, nil
}

func (e *ScanExecutor) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

func (e *ScanExecutor) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

func (e *ScanExecutor) wait(ctx context.Context, d time.Duration) error {
	if e.sleep != nil {
		return e.sleep(ctx, d)
	}
	return sleepCtx(ctx, d)
}

// admit checks the payload against the connector config and the local
// policy before any Tenable.sc call. One violation refuses the whole job.
func (e *ScanExecutor) admit(ctx context.Context, raw json.RawMessage) (*scanJob, error) {
	if len(raw) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: payload larger than %d bytes", ErrRefused, maxPayloadBytes)
	}
	var p ScanPayload
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
	a := inst.Allow
	if !a.Operations[OperationScan] {
		return nil, fmt.Errorf("%w: the sensor owner does not allow scans on instance %q", ErrRefused, inst.Name)
	}
	if !slices.Contains(a.ScanPolicies, p.PolicyID) {
		return nil, fmt.Errorf("%w: scan policy %d is not allowed by the sensor owner", ErrRefused, p.PolicyID)
	}
	if !slices.Contains(a.ScanRepositories, p.RepositoryID) {
		return nil, fmt.Errorf("%w: repository %d is not allowed for scans by the sensor owner", ErrRefused, p.RepositoryID)
	}
	if p.ZoneID < 0 || (p.ZoneID > 0 && !slices.Contains(a.ScanZones, p.ZoneID)) {
		return nil, fmt.Errorf("%w: scan zone %d is not allowed by the sensor owner", ErrRefused, p.ZoneID)
	}
	job := &scanJob{inst: inst, policyID: p.PolicyID, repoID: p.RepositoryID, zoneID: p.ZoneID}
	job.maxSeconds = a.MaxScanSeconds
	if p.MaxScanSeconds < 0 {
		return nil, fmt.Errorf("%w: max_scan_seconds must not be negative", ErrRefused)
	}
	if p.MaxScanSeconds > 0 {
		job.maxSeconds = min(p.MaxScanSeconds, a.MaxScanSeconds)
	}
	job.minSeverity = defaultMinSeverity
	if p.MinSeverity != nil {
		if *p.MinSeverity < 0 || *p.MinSeverity > 4 {
			return nil, fmt.Errorf("%w: min_severity must be 0..4", ErrRefused)
		}
		job.minSeverity = *p.MinSeverity
	}
	if len(p.Targets) == 0 {
		return nil, fmt.Errorf("%w: the job names no target", ErrRefused)
	}
	if len(p.Targets) > a.MaxTargetsPerScan {
		return nil, fmt.Errorf("%w: %d targets, more than the %d the sensor owner allows per scan", ErrRefused, len(p.Targets), a.MaxTargetsPerScan)
	}
	seen := map[string]bool{}
	var total int64
	for _, raw := range p.Targets {
		t, n, err := checkScanTarget(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: target %q: %v", ErrRefused, sanitizeText(raw, 80), err)
		}
		if e.Policy != nil {
			if err := e.Policy.CheckTarget(ctx, t); err != nil {
				return nil, fmt.Errorf("%w: target %q is outside this sensor's local policy: %v", ErrRefused, t, err)
			}
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		total += n
		if total > int64(a.MaxTargetsPerScan) {
			return nil, fmt.Errorf("%w: the targets cover more than the %d addresses the sensor owner allows per scan", ErrRefused, a.MaxTargetsPerScan)
		}
		job.targets = append(job.targets, t)
	}
	job.addresses = total
	return job, nil
}

var scanHostnameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// blockedTargetPrefixes are never scanned, whatever the policy: loopback,
// link-local (cloud metadata), CGNAT, "this" network, multicast, reserved,
// broadcast, unspecified and the IPv6 metadata endpoints.
var blockedTargetPrefixes = mustPrefixes(
	"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
	"255.255.255.255/32", "::1/128", "::/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "fd20:ce::254/128",
)

var blockedHostnames = []string{"localhost", "metadata", "metadata.google.internal", "metadata.goog", "instance-data"}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// checkScanTarget validates one target and returns it normalized with the
// number of addresses it covers. Accepted: an IP address, a CIDR (IPv4 /16
// or narrower, IPv6 /120 or narrower) or a host name. Refused: URLs, ports,
// lists, whitespace and anything in blockedTargetPrefixes.
func checkScanTarget(raw string) (string, int64, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", 0, errors.New("empty target")
	}
	if strings.Contains(t, "://") || strings.ContainsAny(t, " \t\r\n,;@?#[]") {
		return "", 0, errors.New("only one IP address, CIDR range or host name is accepted (no URLs, lists or spaces)")
	}
	if pfx, err := netip.ParsePrefix(t); err == nil {
		pfx = pfx.Masked()
		bits := pfx.Bits()
		hostBits := pfx.Addr().BitLen() - bits
		if pfx.Addr().Is4() && bits < minIPv4PrefixBits {
			return "", 0, fmt.Errorf("IPv4 ranges wider than /%d are refused", minIPv4PrefixBits)
		}
		if pfx.Addr().Is6() && bits < minIPv6PrefixBits {
			return "", 0, fmt.Errorf("IPv6 ranges wider than /%d are refused", minIPv6PrefixBits)
		}
		for _, b := range blockedTargetPrefixes {
			if b.Overlaps(pfx) {
				return "", 0, errors.New("the range includes loopback, link-local, metadata, multicast or reserved addresses")
			}
		}
		n := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
		return pfx.String(), n.Int64(), nil
	}
	if strings.Contains(t, "/") {
		return "", 0, errors.New("not a valid CIDR range")
	}
	if addr, err := netip.ParseAddr(t); err == nil {
		if addr.Zone() != "" {
			return "", 0, errors.New("zoned IPv6 addresses are refused")
		}
		addr = addr.Unmap()
		for _, b := range blockedTargetPrefixes {
			if b.Contains(addr) {
				return "", 0, errors.New("loopback, link-local, metadata, multicast or reserved address")
			}
		}
		if net.IP(addr.AsSlice()).IsUnspecified() {
			return "", 0, errors.New("unspecified address")
		}
		return addr.String(), 1, nil
	}
	if strings.Contains(t, ":") {
		return "", 0, errors.New("ports and URLs are refused")
	}
	h := strings.ToLower(strings.TrimSuffix(t, "."))
	if len(h) > maxHostnameLen || !scanHostnameRE.MatchString(h) {
		return "", 0, errors.New("not a valid host name")
	}
	for _, b := range blockedHostnames {
		if h == b || strings.HasSuffix(h, "."+b) || strings.HasSuffix(h, ".localhost") {
			return "", 0, errors.New("loopback or metadata host name")
		}
	}
	return h, 1, nil
}

type scanRun struct {
	e      *ScanExecutor
	job    *scanJob
	client *Client
	cmdID  string
	ctx    context.Context

	version   string
	license   *License
	defID     string
	resultID  string
	state     ScanResultState
	coverage  string
	stopped   bool
	timedOut  bool
	deleted   bool
	deleteErr string
	open      int
	hosts     int
	plugins   int
	reports   int
}

// Final Tenable.sc states. Anything else is still in progress.
var (
	finalScanStatuses   = map[string]bool{"completed": true, "error": true, "partial": true, "stopped": true, "canceled": true, "cancelled": true, "failed": true}
	finalImportStatuses = map[string]bool{"finished": true, "completed": true, "error": true, "no results": true, "blocked": true, "failed": true}
	goodImportStatuses  = map[string]bool{"finished": true, "completed": true}
)

func (r *scanRun) execute() (map[string]any, error) {
	err := r.run()
	// The definition this run created is deleted whatever happened.
	r.cleanup()
	if err != nil {
		return nil, err
	}
	return r.metadata(), nil
}

func (r *scanRun) run() error {
	sys, err := r.client.System(r.ctx)
	if err != nil {
		return err
	}
	r.version = sys.Version
	if lic, err := r.client.Status(r.ctx); err == nil {
		r.license = &lic
	} else if errors.Is(err, ErrCredentialsRejected) || r.ctx.Err() != nil {
		return err
	}

	r.defID, err = r.client.CreateScan(r.ctx, ScanSpec{
		Name:         "openctem-" + sanitizeIdentifier(r.cmdID),
		PolicyID:     r.job.policyID,
		RepositoryID: r.job.repoID,
		ZoneID:       r.job.zoneID,
		Targets:      r.job.targets,
		MaxScanTime:  r.job.maxSeconds,
	})
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}

	r.resultID, err = r.client.LaunchScan(r.ctx, r.defID)
	if err != nil {
		return fmt.Errorf("launch scan: %w", err)
	}
	r.e.logf("tenable.sc %s: scan result %s launched on %d target(s)", r.job.inst.Name, r.resultID, len(r.job.targets))

	if err := r.poll(); err != nil {
		return err
	}

	r.coverage = CoveragePartial
	if strings.EqualFold(r.state.Status, "completed") && goodImportStatuses[strings.ToLower(r.state.ImportStatus)] && !r.stopped {
		r.coverage = CoverageFull
	}
	if finalImportStatuses[strings.ToLower(r.state.ImportStatus)] && !strings.EqualFold(r.state.ImportStatus, "error") &&
		!strings.EqualFold(r.state.ImportStatus, "blocked") && !strings.EqualFold(r.state.ImportStatus, "failed") {
		if err := r.pull(); err != nil {
			return err
		}
	}
	return nil
}

// poll waits for the scan result to finish and its import to end. Past the
// deadline the scan is stopped and the run is partial; a cancelled command
// stops the scan and fails.
func (r *scanRun) poll() error {
	interval := r.e.pollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	deadline := r.e.clock().Add(time.Duration(r.job.maxSeconds)*time.Second + importGrace)
	for {
		st, err := r.client.ScanResult(r.ctx, r.resultID)
		if err != nil {
			if r.ctx.Err() != nil {
				r.stop()
				return r.ctx.Err()
			}
			return fmt.Errorf("scan result %s: %w", r.resultID, err)
		}
		r.state = st
		if finalScanStatuses[strings.ToLower(st.Status)] && finalImportStatuses[strings.ToLower(st.ImportStatus)] {
			return nil
		}
		if !r.e.clock().Before(deadline) {
			r.timedOut = true
			r.stop()
			// Read the state once more: a stop imports what was scanned.
			if st, err := r.client.ScanResult(r.ctx, r.resultID); err == nil {
				r.state = st
			}
			return nil
		}
		if err := r.e.wait(r.ctx, interval); err != nil {
			r.stop()
			return err
		}
	}
}

// stop stops the scan result this run launched, with a context of its own
// so a cancelled command still stops it.
func (r *scanRun) stop() {
	if r.resultID == "" || r.stopped {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), cleanupTimeout)
	defer cancel()
	if err := r.client.StopScanResult(ctx, r.resultID); err != nil {
		r.e.logf("tenable.sc %s: stopping scan result %s failed: %v", r.job.inst.Name, r.resultID, err)
	}
	r.stopped = true
}

// cleanup deletes the scan definition this run created (its results stay).
func (r *scanRun) cleanup() {
	if r.defID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), cleanupTimeout)
	defer cancel()
	if err := r.client.DeleteScan(ctx, r.defID); err != nil {
		r.deleteErr = sanitizeText(err.Error(), maxErrorMsgBytes)
		r.e.logf("tenable.sc %s: deleting scan definition %s failed: %v", r.job.inst.Name, r.defID, err)
		return
	}
	r.deleted = true
}

// pull reads the scan result's findings and hosts and pushes them.
func (r *scanRun) pull() error {
	sr := &syncRun{
		e:      &SyncExecutor{Config: r.e.Config, Pusher: r.e.Pusher, Logf: r.e.Logf, now: r.e.now},
		client: r.client, cmdID: r.cmdID, ctx: r.ctx,
		job: &syncJob{
			inst: r.job.inst, mode: ModeFull, minSeverity: r.job.minSeverity,
			include:      map[string]bool{IncludeVulns: true, IncludeHosts: true, IncludePlugins: true},
			repositories: []int{r.job.repoID},
			scanResultID: r.resultID, coverage: r.coverage,
		},
		mapper:  &mapper{now: r.e.clock(), plugins: map[string]*plugin{}},
		emitted: map[string]bool{},
		ipSeen:  map[string]*hostSeen{},
		version: r.version,
	}
	if err := sr.query(sr.vulnQuery("individual"), stateOpen); err != nil {
		return fmt.Errorf("read scan result %s: %w", r.resultID, err)
	}
	if err := sr.flush(); err != nil {
		return err
	}
	if err := sr.hosts(); err != nil {
		return fmt.Errorf("read scan result %s hosts: %w", r.resultID, err)
	}
	if err := sr.flush(); err != nil {
		return err
	}
	r.open, r.hosts, r.plugins, r.reports = sr.counts.open, sr.counts.hosts, sr.counts.plugins, sr.counts.reports
	return nil
}

func (r *scanRun) metadata() map[string]any {
	md := map[string]any{
		"connector":          ToolName,
		"instance":           r.job.inst.Name,
		"tenable_version":    r.version,
		"scan_result_id":     r.resultID,
		"scan_status":        r.state.Status,
		"import_status":      r.state.ImportStatus,
		"coverage":           r.coverage,
		"targets":            len(r.job.targets),
		"addresses":          r.job.addresses,
		"policy_id":          r.job.policyID,
		"repository_id":      r.job.repoID,
		"hosts":              r.hosts,
		"open":               r.open,
		"plugins":            r.plugins,
		"reports":            r.reports,
		"stopped":            r.stopped,
		"timed_out":          r.timedOut,
		"definition_deleted": r.deleted,
	}
	if r.job.zoneID > 0 {
		md["zone_id"] = r.job.zoneID
	}
	if r.state.TotalChecks > 0 {
		md["completed_checks"] = r.state.CompletedChecks
		md["total_checks"] = r.state.TotalChecks
	}
	if r.license != nil {
		md["licensed_ips"] = r.license.LicensedIPs
		md["active_ips"] = r.license.ActiveIPs
	}
	if r.deleteErr != "" {
		md["warnings"] = []string{"the scan definition could not be deleted: " + r.deleteErr}
	}
	return md
}
