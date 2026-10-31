// Package recon runs the ProjectDiscovery recon tools (subfinder, dnsx,
// naabu, httpx, katana) as ordinary scanners.
//
// Each tool's package implements core.ReconScanner, which returns typed
// results (subdomains, DNS records, open ports, live hosts, URLs). A sensor's
// command executor runs core.Scanner and reads its raw output with a parser.
// Scanner bridges the two: it runs the recon tool on every target, converts
// the results with ctis.ConvertReconToCTIS (the one recon-to-CTIS converter)
// and returns the CTIS report as its raw output, which the generic CTIS JSON
// parser reads. Discovered hosts, IPs, services and URLs then reach the
// platform as assets through normal ingest.
package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	webctis "github.com/openctemio/ctis"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/reachobs"
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/internal/resolv"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/recon/subfinder"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Tools are the recon tools this package runs, in pipeline order.
var Tools = []string{"subfinder", "dnsx", "dnsx-enum", "naabu", "httpx", "katana"}

// capabilities are the capability names the platform's tool catalog gives
// each recon tool. A sensor advertises them, and the platform offers a job
// whose required capabilities they cover.
var capabilities = map[string][]string{
	"subfinder": {"recon", "subdomain"},
	"dnsx":      {"recon", "dns"},
	"dnsx-enum": {"recon", "subdomain_enum"},
	"naabu":     {"recon", "portscan"},
	"httpx":     {"recon", "http", "tech_detect"},
	"katana":    {"recon", "crawler", "url_discovery"},
}

// Capabilities returns the platform capability names of a recon tool, or
// nil for a name that is not one.
func Capabilities(tool string) []string {
	caps := capabilities[tool]
	if caps == nil {
		return nil
	}
	return append([]string(nil), caps...)
}

// IsTool reports whether name is a recon tool this package runs.
func IsTool(name string) bool {
	_, ok := capabilities[name]
	return ok
}

// New returns the recon tool name as a core.Scanner, with the tool's
// defaults (naabu: connect scan of the top 100 ports, no root needed). An
// unknown name is an error.
func New(name string) (*Scanner, error) {
	var rs core.ReconScanner
	switch name {
	case "subfinder":
		rs = subfinder.NewScanner()
	case "dnsx":
		rs = dnsx.NewScanner()
	case dnsx.EnumName:
		rs = dnsx.NewEnumScanner()
	case "naabu":
		rs = naabu.NewScanner()
	case "httpx":
		rs = httpx.NewScanner()
	case "katana":
		rs = katana.NewScanner()
	default:
		return nil, fmt.Errorf("unknown recon tool: %s", name)
	}
	return NewScanner(rs), nil
}

// Scanner runs a core.ReconScanner as a core.Scanner whose raw output is a
// CTIS report. It is a core.MultiTargetScanner: a job with several targets
// runs the tool on each in turn and returns one report.
type Scanner struct {
	recon core.ReconScanner
	caps  []string
	// Options are passed to every recon run (threads, rate limit,
	// resolvers). The job's extra arguments and environment are added.
	Options core.ReconOptions
}

// NewScanner wraps rs. It advertises the platform capabilities of rs's
// tool, or rs's recon type for a tool the catalog does not know.
func NewScanner(rs core.ReconScanner) *Scanner {
	caps := Capabilities(rs.Name())
	if caps == nil {
		caps = []string{"recon", string(rs.Type())}
	}
	return &Scanner{recon: rs, caps: caps}
}

// Recon returns the wrapped recon scanner (to adjust its settings).
func (s *Scanner) Recon() core.ReconScanner { return s.recon }

// Name returns the tool name.
func (s *Scanner) Name() string { return s.recon.Name() }

// Version returns the tool version (known after IsInstalled).
func (s *Scanner) Version() string { return s.recon.Version() }

// Capabilities returns the platform capabilities of the tool.
func (s *Scanner) Capabilities() []string { return append([]string(nil), s.caps...) }

// IsInstalled reports whether the tool's binary answers its version flag.
// A binary that is on PATH but does not run is not installed: the sensor
// must not advertise a tool it cannot run.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	return s.recon.IsInstalled(ctx)
}

// settingsTool is a recon tool with typed per-scan settings (api RFC-038).
type settingsTool interface {
	core.SettingsSchemaProvider
	// WithSettings returns the tool configured for one scan, without
	// modifying the tool itself.
	WithSettings(*core.ToolSettings) (core.ReconScanner, error)
}

// SettingsSchema returns the tool's settings schema, or nil when it has
// none (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema {
	if t, ok := s.recon.(settingsTool); ok {
		return t.SettingsSchema()
	}
	return nil
}

// forScan is the tool configured with a scan's settings. A tool without
// settings refuses them: the executor gives settings only to a scanner that
// declares a schema, so anything else is a bug that must not run silently.
func (s *Scanner) forScan(opts *core.ScanOptions) (core.ReconScanner, error) {
	rs := s.recon
	if opts != nil && opts.Settings != nil {
		t, ok := s.recon.(settingsTool)
		if !ok {
			return nil, fmt.Errorf("%s takes no settings", s.recon.Name())
		}
		var err error
		if rs, err = t.WithSettings(opts.Settings); err != nil {
			return nil, err
		}
	}
	if opts != nil && opts.Capability != "" {
		// A tool that runs differently per capability (naabu: port scan or
		// host discovery) is configured for the job's.
		if t, ok := rs.(capabilityTool); ok {
			var err error
			if rs, err = t.WithCapability(opts.Capability); err != nil {
				return nil, err
			}
		}
	}
	if opts != nil && opts.WebScope != nil {
		// A tool that cannot keep to the web scope never runs without it.
		t, ok := rs.(webScopeTool)
		if !ok {
			return nil, fmt.Errorf("%s does not keep to a web scope; the job has one", s.recon.Name())
		}
		var err error
		if rs, err = t.WithWebScope(opts.WebScope); err != nil {
			return nil, err
		}
	}
	if opts != nil && len(opts.ExcludeHosts) > 0 {
		// The job's exclusions reach a tool that can skip hosts itself; the
		// SDK already cut the job's ranges around them.
		if t, ok := rs.(excludeHostsTool); ok {
			var err error
			if rs, err = t.WithExcludeHosts(opts.ExcludeHosts); err != nil {
				return nil, err
			}
		}
	}
	if opts != nil && len(opts.Limits) > 0 {
		// The task's forwarder enforces the limits; the tool is also told
		// to keep to them where it has flags for it (fewer refused
		// requests), never instead of the forwarder.
		if t, ok := rs.(scopeLimitTool); ok {
			return t.WithScopeLimits(scopelimit.NewSet(opts.Limits))
		}
	}
	return rs, nil
}

// excludeHostsTool is a recon tool that can skip a job's excluded hosts
// (naabu -exclude-hosts).
type excludeHostsTool interface {
	WithExcludeHosts(hosts []string) (core.ReconScanner, error)
}

// capabilityTool is a recon tool configured per capability job.
type capabilityTool interface {
	WithCapability(ref string) (core.ReconScanner, error)
}

// hostDiscoverer is a recon tool that can run as host discovery: its report
// keeps only the live addresses, each with the probe that answered.
type hostDiscoverer interface {
	HostDiscoveryMode() bool
}

// scopeLimitTool is a recon tool that maps a job's scope limits onto its
// flags (naabu: the port list; katana: the crawl's path prefixes).
type scopeLimitTool interface {
	WithScopeLimits(scopelimit.Set) (core.ReconScanner, error)
}

// identityTool is a recon tool that sends the job's identification (a
// program's User-Agent and headers) on every request (httpx, katana).
type identityTool interface {
	WithIdentity(*tool.Identity) (core.ReconScanner, error)
}

// webScopeTool is a recon tool that keeps to a job's web scope (katana).
type webScopeTool interface {
	WithWebScope(*webscope.Scope) (core.ReconScanner, error)
}

// Scan runs the tool on one target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// resolvingTools resolve host names through their own resolver lists (-r;
// built-in public resolvers without one). httpx and katana use the
// system resolver already.
var resolvingTools = []string{"dnsx", "dnsx-enum", "naabu", "subfinder"}

// sensorResolvers returns the sensor's resolvers (a var for tests).
var sensorResolvers = resolv.Sensor

// ErrToolFailed reports a recon run that did not complete. Its results are
// not reported: a failed run must fail its job, not complete with 0 assets.
var ErrToolFailed = errors.New("recon tool failed")

// ScanTargets runs the tool on each target and returns one CTIS report with
// everything found. A target the tool could not complete (over its budget,
// unreachable, or its run failed) is that target's outcome, listed in the
// report; the job fails only when the tool itself failed on every target.
// When the job's time budget ends the run, the finished targets' report is
// returned (partial, with the unfinished targets listed).
//
// A tool ported to the tool contract (httpx) runs out of process, in the
// task sandbox (tool.go); the others run here.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if p := s.port(); p != nil {
		var jobErr error
		if ctx, opts, jobErr = toolrun.ApplyJob(ctx, p.manifest, s.SettingsSchema(), opts); jobErr != nil {
			return nil, jobErr
		}
	} else if opts != nil && (opts.Capability != "" || len(opts.Params) > 0 || opts.MaxTier != "" || opts.WebScope != nil || len(opts.Limits) > 0) {
		return nil, fmt.Errorf("%s does not run capability jobs", s.recon.Name())
	}
	if res, ran, err := s.outOfProcess(ctx, targets, opts); ran {
		return res, err
	}
	res, obs, err := s.scanTargets(ctx, targets, opts, nil)
	// What the tool saw toward each target: the job's reach summary.
	reachobs.Record(ctx, targets, obs)
	if err != nil && res != nil && errors.Is(err, context.DeadlineExceeded) {
		// The job's time budget ended the run: what it finished is
		// delivered (partial); a cancel delivers nothing.
		return res, nil
	}
	return res, err
}

// settleFunc is told each target's outcome the moment the target ends: i is
// its index in the job's targets, err nil when it completed. A *targetError
// says why it did not.
type settleFunc func(i int, err error)

// targetError is why one target did not complete: over its budget, not
// reached (a reach outcome the tool reported), or its run failed. Only the
// last is the tool's own failure.
type targetError struct {
	err      error
	timedOut bool
	reach    bool
}

func (e *targetError) Error() string { return e.err.Error() }
func (e *targetError) Unwrap() error { return e.err }

// toolLevel reports whether the error is the tool's own failure rather than
// the target's (a target over its budget or out of reach says nothing about
// the tool).
func (e *targetError) toolLevel() bool { return !e.timedOut && !e.reach }

// reachObserver is a recon tool that reads, from one target's result,
// what it saw toward the target: an answer, a closed port, no route, a
// timeout, a name that does not resolve (api RFC-089).
type reachObserver interface {
	ReachObservations(target string, res *core.ReconResult) []reachobs.Obs
}

// scanTargets is the direct path: the tool runs as this process's child.
// obs are the reach outcomes it saw, also when it failed.
//
// settle, when not nil, is told each target's outcome as it ends (the tool
// child streams it as the task's progress). When ctx ends, the report of the
// targets finished so far is returned with ctx's error, the unfinished
// targets listed; the caller decides whether it is delivered.
func (s *Scanner) scanTargets(ctx context.Context, targets []string, opts *core.ScanOptions, settle settleFunc) (_ *core.ScanResult, obs []reachobs.Obs, _ error) {
	// A batch run may settle a target early (its first record streamed in)
	// and again when the run ends: the caller hears each target once.
	settle = settleOnce(settle)
	start := time.Now()
	name := s.recon.Name()
	tool, err := s.forScan(opts)
	if err != nil {
		return nil, obs, err
	}
	in := &ctis.ReconToCTISInput{
		ScannerName: name,
		ReconType:   string(s.recon.Type()),
		Target:      strings.Join(targets, ","),
		StartedAt:   start.Unix(),
	}
	// One target that does not resolve (naabu exits 1 with "no valid
	// targets") must not discard the others' results; a job where every
	// target failed is a failed job.
	// The resolvers of the tools that resolve names themselves: the
	// sensor's, never their built-in public lists.
	resolvers := s.Options.Resolvers
	if len(resolvers) == 0 && slices.Contains(resolvingTools, name) {
		r, err := sensorResolvers(nil)
		if err != nil {
			return nil, obs, err
		}
		resolvers = r
	}
	// The rate and concurrency of every run: the tool's own, lowered by the
	// scanner's options and the scan's rate_limit / concurrency (already
	// capped at the local policy's rate.max_rps by the executor), never
	// raised (politeness.go).
	ownRate, ownThreads := toolLimits(tool)
	rate := lower(lower(ownRate, s.Options.RateLimit), scanRate(opts))
	threads := lower(lower(ownThreads, s.Options.Threads), scanConcurrency(opts))
	if err := checkHostBoundArgs(s.Options.ExtraArgs); err != nil {
		return nil, obs, err
	}
	if opts != nil {
		if err := checkHostBoundArgs(opts.ExtraArgs); err != nil {
			return nil, obs, err
		}
	}
	var bo backoff
	var failed []failedTarget
	var lastToolErr error
	toolFailures := 0
	var stopErr error
	// unfinished are the targets the job's end stopped before they
	// settled.
	var unfinished []string
	// runOptions are one run's options: the scanner's, with the job's
	// limits, resolvers, budget and extra arguments.
	runOptions := func() core.ReconOptions {
		ro := s.Options
		ro.RateLimit = lower(rate, bo.rate)
		ro.Threads = threads
		ro.Resolvers = resolvers
		ro.Timeout = targetTimeout(ro.Timeout, opts)
		if opts != nil {
			ro.ExtraArgs = append(append([]string(nil), ro.ExtraArgs...), opts.ExtraArgs...)
			if len(opts.Env) > 0 {
				ro.Env = mergeEnv(ro.Env, opts.Env)
			}
			ro.Verbose = ro.Verbose || opts.Verbose
		}
		return ro
	}
	// settleTarget records target i's outcome: its result, or why it did
	// not complete.
	settleTarget := func(i int, t string, ro *core.ReconOptions, res *core.ReconResult, err error, timedOut bool) {
		// Settled (found, nothing, failed or over its budget): one more
		// finished target on the heartbeat's progress.
		core.TargetDone(ctx, t)
		if err == nil && slices.Contains(throttleTools, name) && throttled(res) {
			bo.hit(t, ro.RateLimit)
		}
		if err == nil {
			err = runError(res)
		}
		if timedOut {
			err = &targetError{err: fmt.Errorf("over its time budget of %s", ro.Timeout), timedOut: true}
			obs = append(obs, reachobs.Obs{Target: t, Class: reach.Timeout, Detail: "over its time budget"})
		}
		if err != nil {
			te, ok := err.(*targetError)
			if !ok {
				te = &targetError{err: err}
				// Only a tool that reaches its targets reads a failure as a
				// reach outcome (not a passive source lookup).
				if _, reaches := tool.(reachObserver); reaches {
					if o, ok := reachobs.Failure(t, err.Error()); ok {
						obs = append(obs, o)
						te.reach = true
					}
				}
			}
			failed = append(failed, failedTarget{Target: t, Error: te.Error()})
			if te.toolLevel() {
				toolFailures++
				lastToolErr = te.err
			}
			if settle != nil {
				settle(i, te)
			}
			return
		}
		if in.ScannerVersion == "" {
			in.ScannerVersion = res.ScannerVersion
		}
		if ro, ok := tool.(reachObserver); ok {
			obs = append(obs, ro.ReachObservations(t, res)...)
		}
		appendResult(in, res)
		if settle != nil {
			settle(i, nil)
		}
	}
	if bt, ok := tool.(batchTool); ok && len(targets) > 1 && batchable(bt) {
		// One run for the whole list, with the tool's own concurrency, rate
		// and per-probe timeouts; the run is bounded by the job, not by a
		// per-target kill (batch.go).
		unfinished, stopErr = runBatch(ctx, bt, targets, runOptions(), settleTarget, func(i int) {
			// The target's first record streamed in: settled done now.
			core.TargetDone(ctx, targets[i])
			if settle != nil {
				settle(i, nil)
			}
		})
	} else {
		for i, t := range targets {
			if err := ctx.Err(); err != nil {
				stopErr, unfinished = err, targets[i:]
				break
			}
			if i > 0 {
				if err := sleepFn(ctx, &bo); err != nil {
					stopErr, unfinished = err, targets[i:]
					break
				}
			}
			ro := runOptions()
			ro.Target = t
			// The target's own budget: past it, only this target is cut and
			// the next one goes on.
			tctx, cancel := ctx, context.CancelFunc(func() {})
			if ro.Timeout > 0 {
				tctx, cancel = context.WithTimeout(ctx, ro.Timeout)
			}
			res, err := tool.Scan(tctx, t, &ro)
			timedOut := ro.Timeout > 0 && ctx.Err() == nil && errors.Is(tctx.Err(), context.DeadlineExceeded)
			cancel()
			if ctxErr := ctx.Err(); ctxErr != nil {
				// The job ended during this target: it is unfinished.
				stopErr, unfinished = ctxErr, targets[i:]
				break
			}
			settleTarget(i, t, &ro, res, err, timedOut)
		}
	}
	finishedCount := len(targets) - len(unfinished)
	if stopErr != nil && finishedCount == 0 {
		return nil, obs, stopErr
	}
	// The tool failing on every target is the tool's failure, not the
	// targets': the job fails. Targets over their budget or out of reach
	// are outcomes of a run that worked.
	if stopErr == nil && len(targets) > 0 && toolFailures == len(targets) {
		if len(targets) == 1 {
			return nil, obs, fmt.Errorf("%w: %s on %s: %w", ErrToolFailed, name, targets[0], lastToolErr)
		}
		return nil, obs, fmt.Errorf("%w: %s failed on all %d targets, last: %w", ErrToolFailed, name, len(targets), lastToolErr)
	}
	finished := time.Now()
	in.FinishedAt = finished.Unix()
	in.DurationMs = finished.Sub(start).Milliseconds()
	if in.ScannerVersion == "" {
		in.ScannerVersion = s.recon.Version()
	}

	convOpts := ctis.DefaultReconConverterOptions()
	convOpts.DiscoveryTool = name
	report, err := ctis.ConvertReconToCTIS(in, convOpts)
	if err != nil {
		return nil, obs, fmt.Errorf("convert %s results: %w", name, err)
	}
	if hd, ok := tool.(hostDiscoverer); ok && hd.HostDiscoveryMode() {
		core.LiveHostsReport(report, targets)
	}
	if len(failed) > 0 {
		if report.Properties == nil {
			report.Properties = ctis.Properties{}
		}
		report.Properties["failed_targets"] = failed
	}
	if stopErr != nil {
		// The job ended part-way: the targets not finished are listed, and
		// nothing may be read as covered beyond the finished ones.
		if report.Properties == nil {
			report.Properties = ctis.Properties{}
		}
		report.Properties[unfinishedTargetsKey] = append([]string(nil), unfinished...)
		report.Metadata.CoverageType = "partial"
	}
	if len(bo.hosts) > 0 {
		if report.Properties == nil {
			report.Properties = ctis.Properties{}
		}
		report.Properties["target_throttled"] = true
		report.Properties["throttled_targets"] = bo.hosts
		report.Properties["throttled_rate_limit"] = bo.rate
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, obs, fmt.Errorf("encode %s report: %w", name, err)
	}
	res := &core.ScanResult{
		ScannerName:    name,
		ScannerVersion: in.ScannerVersion,
		StartedAt:      in.StartedAt,
		FinishedAt:     in.FinishedAt,
		DurationMs:     in.DurationMs,
		RawOutput:      raw,
	}
	if stopErr != nil {
		res.Error = fmt.Sprintf("%s stopped after %d of %d targets: %v", name, finishedCount, len(targets), stopErr)
	}
	return res, obs, stopErr
}

// unfinishedTargetsKey is the report property listing the targets a run the
// job's end stopped never reached (the same key the tool runtime uses).
const unfinishedTargetsKey = "unfinished_targets"

// targetTimeout is one target's run timeout: the platform's per-target
// budget (research note 122 in openctem) when it is shorter than the
// configured one, so one host that never answers costs one budget and the
// other targets go on. A budget never lengthens the configured timeout.
func targetTimeout(configured time.Duration, opts *core.ScanOptions) time.Duration {
	if opts == nil || opts.TargetTimeout <= 0 {
		return configured
	}
	if configured > 0 && configured < opts.TargetTimeout {
		return configured
	}
	return opts.TargetTimeout
}

// scanRate and scanConcurrency are a scan's requested limits (0: none).
func scanRate(opts *core.ScanOptions) int {
	if opts == nil {
		return 0
	}
	return opts.RateLimit
}

func scanConcurrency(opts *core.ScanOptions) int {
	if opts == nil {
		return 0
	}
	return opts.Concurrency
}

// failedTarget is a target the tool did not complete on, reported in the
// CTIS report's properties ("failed_targets").
type failedTarget struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// runError is the failure of a recon run that returned a result: the
// wrapper's error, a missing result, or a non-zero exit. The
// ProjectDiscovery tools exit 0 when they finish, results or not; any other
// exit (an unknown flag exits 2, no valid input 1) means the run did not
// happen.
func runError(res *core.ReconResult) error {
	switch {
	case res == nil:
		return errors.New("no result")
	case res.Error != "":
		return errors.New(res.Error)
	case res.ExitCode != 0:
		return fmt.Errorf("exited with status %d", res.ExitCode)
	}
	return nil
}

// appendResult adds one run's results to the converter input.
func appendResult(in *ctis.ReconToCTISInput, r *core.ReconResult) {
	for _, s := range r.Subdomains {
		in.Subdomains = append(in.Subdomains, ctis.SubdomainInput{Host: s.Host, Domain: s.Domain, Source: s.Source, IPs: s.IPs})
	}
	for _, d := range r.DNSRecords {
		in.DNSRecords = append(in.DNSRecords, ctis.DNSRecordInput{
			Host: d.Host, RecordType: d.RecordType, Values: d.Values, TTL: d.TTL, Resolver: d.Resolver, StatusCode: d.StatusCode,
		})
	}
	for _, p := range r.OpenPorts {
		in.OpenPorts = append(in.OpenPorts, ctis.OpenPortInput{
			Host: p.Host, IP: p.IP, Port: p.Port, Protocol: p.Protocol, Service: p.Service, Version: p.Version, Banner: p.Banner,
		})
	}
	for _, h := range r.LiveHosts {
		in.LiveHosts = append(in.LiveHosts, ctis.LiveHostInput{
			URL: h.URL, Host: h.Host, IP: h.IP, Port: h.Port, Scheme: h.Scheme, StatusCode: h.StatusCode,
			ContentLength: h.ContentLength, Title: h.Title, WebServer: h.WebServer, ContentType: h.ContentType,
			Technologies: h.Technologies, CDN: h.CDN, TLSVersion: h.TLSVersion, Redirect: h.Redirect, ResponseTime: h.ResponseTime,
			CDNType: h.CDNType, TLS: tlsLeaf(h.TLS), FaviconMMH3: h.FaviconMMH3, JARM: h.JARM, ASN: asnInput(h.ASN),
			ResponseHeaders: responseHeaders(h.ResponseHeaders), CNAMEs: core.SanitizeCNAMEs(h.CNAMEs),
			WebContent: webCaptures(h.WebContent),
		})
	}
	for _, u := range r.URLs {
		in.URLs = append(in.URLs, ctis.DiscoveredURLInput{
			URL: u.URL, Method: u.Method, Source: u.Source, StatusCode: u.StatusCode, Depth: u.Depth,
			Parent: u.Parent, Type: u.Type, Extension: u.Extension,
			ContentType: u.ContentType, Params: urlParams(u.Params), Forms: webForms(u.Forms),
		})
	}
	for _, t := range r.Technologies {
		in.Technologies = append(in.Technologies, ctis.TechnologyInput{
			Name: t.Name, Version: t.Version, Categories: t.Categories, Confidence: t.Confidence, Website: t.Website,
		})
	}
}

// webCaptures converts a web content job's captures for the CTIS converter,
// which bounds every field again.
func webCaptures(in []core.WebCapture) []ctis.WebCaptureInput {
	var out []ctis.WebCaptureInput
	for _, c := range in {
		out = append(out, ctis.WebCaptureInput{
			URL: c.URL, FinalURL: c.FinalURL, StatusCode: c.StatusCode, ContentType: c.ContentType, Size: c.Size,
			SHA256: c.SHA256, Truncated: c.Truncated, Body: c.Body, BodyTruncated: c.BodyTruncated, FetchedAt: c.FetchedAt,
		})
	}
	return out
}

// responseHeaders converts a probe's posture headers for the CTIS converter.
// Bound re-applies the allow-list, so a value built or decoded elsewhere
// cannot carry a header or a cookie value past the sensor.
func responseHeaders(r *core.ResponseHeaders) *webctis.ResponseHeadersInput {
	r = r.Bound()
	if r == nil {
		return nil
	}
	out := &webctis.ResponseHeadersInput{Values: r.Values}
	for _, c := range r.Cookies {
		out.Cookies = append(out.Cookies, webctis.CookieFlagsInput{
			Name: c.Name, Secure: c.Secure, HTTPOnly: c.HTTPOnly, SameSite: c.SameSite, Persistent: c.Persistent,
		})
	}
	return out
}

func urlParams(in []core.URLParam) []ctis.EndpointParam {
	var out []ctis.EndpointParam
	for _, p := range in {
		out = append(out, ctis.EndpointParam{Location: ctis.ParamLocation(p.Location), Name: p.Name})
	}
	return out
}

// webForms converts a page's forms. A field the crawler flagged as a
// password (PasswordField) carries the password type hint, so the platform
// can tell a login form from the field names alone.
func webForms(in []core.WebForm) []webctis.WebFormInput {
	var out []webctis.WebFormInput
	for _, f := range in {
		wf := webctis.WebFormInput{Method: f.Method, Action: f.Action, Params: urlParams(f.Params)}
		if f.PasswordField {
			for i, p := range wf.Params {
				if core.IsPasswordFieldName(p.Name) {
					wf.Params[i].TypeHint = webctis.TypeHintPassword
				}
			}
		}
		out = append(out, wf)
	}
	return out
}

// tlsLeaf converts a probe's leaf certificate for the CTIS converter, which
// bounds and validates every value.
func tlsLeaf(l *core.TLSLeaf) *ctis.TLSLeafInput {
	if l == nil {
		return nil
	}
	return &ctis.TLSLeafInput{
		SubjectCN: l.SubjectCN, SANs: l.SANs, IssuerCN: l.IssuerCN, IssuerOrg: l.IssuerOrg,
		SerialNumber: l.SerialNumber, NotBefore: l.NotBefore, NotAfter: l.NotAfter,
		FingerprintSHA256: l.FingerprintSHA256, SelfSigned: l.SelfSigned, Expired: l.Expired,
		Wildcard: l.Wildcard, Mismatched: l.Mismatched,
	}
}

func asnInput(a *core.ASN) *ctis.ASNInput {
	if a == nil {
		return nil
	}
	return &ctis.ASNInput{Number: a.Number, Org: a.Org, Country: a.Country}
}

func mergeEnv(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

var _ core.MultiTargetScanner = (*Scanner)(nil)

// settleOnce passes each target's first outcome to settle and drops the
// later ones (safe for concurrent use; nil stays nil).
func settleOnce(settle settleFunc) settleFunc {
	if settle == nil {
		return nil
	}
	var mu sync.Mutex
	done := map[int]bool{}
	return func(i int, err error) {
		mu.Lock()
		first := !done[i]
		done[i] = true
		mu.Unlock()
		if first {
			settle(i, err)
		}
	}
}
