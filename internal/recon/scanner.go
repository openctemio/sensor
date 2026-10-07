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
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/internal/resolv"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/recon/subfinder"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Tools are the recon tools this package runs, in pipeline order.
var Tools = []string{"subfinder", "dnsx", "naabu", "httpx", "katana"}

// capabilities are the capability names the platform's tool catalog gives
// each recon tool. A sensor advertises them, and the platform offers a job
// whose required capabilities they cover.
var capabilities = map[string][]string{
	"subfinder": {"recon", "subdomain"},
	"dnsx":      {"recon", "dns"},
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
	if opts != nil && opts.WebScope != nil {
		// A tool that cannot keep to the web scope never runs without it.
		t, ok := rs.(webScopeTool)
		if !ok {
			return nil, fmt.Errorf("%s does not keep to a web scope; the job has one", s.recon.Name())
		}
		return t.WithWebScope(opts.WebScope)
	}
	return rs, nil
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
var resolvingTools = []string{"dnsx", "naabu", "subfinder"}

// sensorResolvers returns the sensor's resolvers (a var for tests).
var sensorResolvers = resolv.Sensor

// ErrToolFailed reports a recon run that did not complete. Its results are
// not reported: a failed run must fail its job, not complete with 0 assets.
var ErrToolFailed = errors.New("recon tool failed")

// ScanTargets runs the tool on each target and returns one CTIS report with
// everything found. A run that fails on any target fails the whole job.
//
// A tool ported to the tool contract (httpx) runs out of process, in the
// task sandbox (tool.go); the others run here.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if p := s.port(); p != nil {
		var jobErr error
		if ctx, opts, jobErr = toolrun.ApplyJob(ctx, p.manifest, s.SettingsSchema(), opts); jobErr != nil {
			return nil, jobErr
		}
	} else if opts != nil && (opts.Capability != "" || len(opts.Params) > 0 || opts.MaxTier != "" || opts.WebScope != nil) {
		return nil, fmt.Errorf("%s does not run capability jobs", s.recon.Name())
	}
	if res, ran, err := s.outOfProcess(ctx, targets, opts); ran {
		return res, err
	}
	return s.scanTargets(ctx, targets, opts)
}

// scanTargets is the direct path: the tool runs as this process's child.
func (s *Scanner) scanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	name := s.recon.Name()
	tool, err := s.forScan(opts)
	if err != nil {
		return nil, err
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
			return nil, err
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
		return nil, err
	}
	if opts != nil {
		if err := checkHostBoundArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	var bo backoff
	var failed []failedTarget
	var lastErr error
	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i > 0 {
			if err := sleepFn(ctx, &bo); err != nil {
				return nil, err
			}
		}
		ro := s.Options
		ro.Target = t
		ro.RateLimit = lower(rate, bo.rate)
		ro.Threads = threads
		ro.Resolvers = resolvers
		if opts != nil {
			ro.ExtraArgs = append(append([]string(nil), ro.ExtraArgs...), opts.ExtraArgs...)
			if len(opts.Env) > 0 {
				ro.Env = mergeEnv(ro.Env, opts.Env)
			}
			ro.Verbose = ro.Verbose || opts.Verbose
		}
		res, err := tool.Scan(ctx, t, &ro)
		if err == nil && slices.Contains(throttleTools, name) && throttled(res) {
			bo.hit(t, ro.RateLimit)
		}
		if err == nil {
			err = runError(res)
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			failed = append(failed, failedTarget{Target: t, Error: err.Error()})
			lastErr = err
			continue
		}
		if in.ScannerVersion == "" {
			in.ScannerVersion = res.ScannerVersion
		}
		appendResult(in, res)
	}
	if len(targets) > 0 && len(failed) == len(targets) {
		if len(targets) == 1 {
			return nil, fmt.Errorf("%w: %s on %s: %w", ErrToolFailed, name, targets[0], lastErr)
		}
		return nil, fmt.Errorf("%w: %s failed on all %d targets, last: %w", ErrToolFailed, name, len(targets), lastErr)
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
		return nil, fmt.Errorf("convert %s results: %w", name, err)
	}
	if len(failed) > 0 {
		if report.Properties == nil {
			report.Properties = ctis.Properties{}
		}
		report.Properties["failed_targets"] = failed
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
		return nil, fmt.Errorf("encode %s report: %w", name, err)
	}
	return &core.ScanResult{
		ScannerName:    name,
		ScannerVersion: in.ScannerVersion,
		StartedAt:      in.StartedAt,
		FinishedAt:     in.FinishedAt,
		DurationMs:     in.DurationMs,
		RawOutput:      raw,
	}, nil
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
		})
	}
	for _, u := range r.URLs {
		in.URLs = append(in.URLs, ctis.DiscoveredURLInput{
			URL: u.URL, Method: u.Method, Source: u.Source, StatusCode: u.StatusCode, Depth: u.Depth,
			Parent: u.Parent, Type: u.Type, Extension: u.Extension,
		})
	}
	for _, t := range r.Technologies {
		in.Technologies = append(in.Technologies, ctis.TechnologyInput{
			Name: t.Name, Version: t.Version, Categories: t.Categories, Confidence: t.Confidence, Website: t.Website,
		})
	}
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
