// Package svcdetect is the sensor's service detection tool
// (detect.services@1): for each known open port of the signed job it finds
// the application protocol, product, version and CPE with credential-free
// handshakes. It is our own engine, compiled into the sensor and run out of
// process in the task sandbox like the other ported tools; the protocol
// probes are an audited allow-list of praetorian-inc nerva plugins (used as
// a library, Apache-2.0) plus our own SSH, HTTP, LDAP and PostgreSQL probes.
//
// Safety (tier 1, research 441 §6 in the openctem repository):
//   - targets are the job's service values (host:port/transport) only, never
//     a range; every connection goes to that target's host:port through
//     tool.Dial, so on a confined sandbox it passes the task's forwarder
//     (scope, limits, the job's proxy pool) and a refused destination fails;
//   - no probe logs in: the plugins that send credentials, bind, or open
//     sockets of their own are not imported (plugins.go has the audit), the
//     nerva Misconfigs and Deep switches are always false, a plugin is given
//     a dialer that refuses every connection, and every connection is
//     bounded (deadline, bytes read, bytes written);
//   - politeness: at most 2 connections to one host at a time, a rate of
//     services started per second, a budget of connections per service
//     (6 fast, 12 thorough);
//   - output: banners and every string are bounded and cleaned of control
//     characters before they leave the tool (text.go); the tool logs counts,
//     never a banner or an answer;
//   - UDP is opt-in and not probed by this version (no UDP route through the
//     forwarder): a UDP service is skipped with a reason; SCTP never.
package svcdetect

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// ToolYAML is the tool's descriptor (OpenCTEM Tool Contract v1): the one
// place its contract is written.
//
//go:embed tool.yaml
var ToolYAML []byte

// Manifest describes the svcdetect tool.
var Manifest = toolrun.MustManifest(ToolYAML)

// Tool runs svcdetect in the tool child.
var Tool = toolrun.Register(tool.New(Manifest, run))

var settingsSchema = core.MustParseSettingsSchema(string(Manifest.Config))

// Depths.
const (
	DepthFast     = "fast"
	DepthThorough = "thorough"
)

// Defaults and bounds of the configuration (tool.yaml).
const (
	DefaultRate      = 10
	MaxRate          = 1000
	DefaultTimeoutMs = 2000
	MinTimeoutMs     = 100
	MaxTimeoutMs     = 10000
	// Connections per service, by depth.
	BudgetFast     = 6
	BudgetThorough = 12
	// HostConcurrency is the most connections to one host at a time.
	HostConcurrency = 2
)

// Config is the tool's configuration (tool.yaml config), mapped from the
// scan's settings by the sensor and handed to the child in Local.
type Config struct {
	Ports      string   `json:"ports,omitempty"`
	Transports []string `json:"transports,omitempty"`
	Depth      string   `json:"depth,omitempty"`
	Rate       int      `json:"rate,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`
}

// Scanner runs svcdetect as a core.Scanner (and MultiTargetScanner,
// CapabilityScanner, SettingsSchemaProvider, ToolContractProvider).
type Scanner struct{}

// NewScanner is the svcdetect scanner the command executor dispatches.
func NewScanner() *Scanner { return &Scanner{} }

// Name is the tool's name.
func (s *Scanner) Name() string { return Manifest.Name }

// Version is the tool's version (compiled in).
func (s *Scanner) Version() string { return Manifest.Version }

// Capabilities are the registry words of the tool; the capability it
// implements comes from its contract (ToolContract).
func (s *Scanner) Capabilities() []string { return []string{"recon"} }

// IsInstalled: a compiled-in tool is always there.
func (s *Scanner) IsInstalled(context.Context) (bool, string, error) {
	return true, s.Version(), nil
}

// SettingsSchema is the tool's configuration schema.
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// ToolContract names the tool's manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(Manifest) }

// EnforcesScopeLimits: every connection goes through tool.Dial and, on a
// confined sandbox, the task's forwarder, which enforces a job's limits.
func (s *Scanner) EnforcesScopeLimits() bool { return true }

// RoutesEgress: the tool runs out of process through the tool host.
func (s *Scanner) RoutesEgress() bool { return true }

// TakesCapabilityJobs: the tool implements detect.services@1.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(Manifest) }

// Scan probes one service.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// ErrExtraArgs: svcdetect has no command line to add arguments to.
var ErrExtraArgs = errors.New("svcdetect takes no extra arguments")

// ScanTargets probes every service in one task.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	ctx, opts, err := toolrun.ApplyJob(ctx, Manifest, settingsSchema, opts)
	if err != nil {
		return nil, err
	}
	cfg := Config{}
	if opts != nil {
		if len(opts.ExtraArgs) > 0 {
			return nil, fmt.Errorf("svcdetect: %w", ErrExtraArgs)
		}
		if opts.Settings != nil {
			if opts.Settings.SchemaDigest() != settingsSchema.Digest() {
				return nil, errors.New("svcdetect settings: resolved against another schema")
			}
			cfg = configFrom(opts.Settings)
		}
		// The scan's rate limit (already capped by the local policy) only
		// lowers the tool's own.
		if opts.RateLimit > 0 && (cfg.Rate <= 0 || opts.RateLimit < cfg.Rate) {
			cfg.Rate = opts.RateLimit
		}
	}
	res, _, err := toolrun.Run(ctx, Tool, targets, cfg, toolhost.RunOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return res, nil
}

// configFrom maps a scan's settings (checked against the schema) to the
// configuration.
func configFrom(ts *core.ToolSettings) Config {
	var c Config
	if v, ok := ts.String("ports"); ok {
		c.Ports = v
	}
	if v, ok := ts.Strings("transports"); ok {
		c.Transports = v
	}
	if v, ok := ts.String("depth"); ok {
		c.Depth = v
	}
	if v, ok := ts.Int("rate"); ok {
		c.Rate = int(v)
	}
	if v, ok := ts.Int("timeout_ms"); ok {
		c.TimeoutMs = int(v)
	}
	return c
}

// settings is a checked configuration with its defaults filled.
type settings struct {
	ports     portSet
	udp       bool
	thorough  bool
	rate      int
	timeoutMs int
}

// readConfig decodes the child's configuration, checks it and fills the
// defaults. It never widens what the schema allows.
func readConfig(task tool.Task) (settings, error) {
	var c Config
	if len(task.Local) > 0 {
		if err := json.Unmarshal(task.Local, &c); err != nil {
			return settings{}, tool.Invalid("svcdetect: the sensor's task configuration is unreadable")
		}
	}
	s := settings{rate: DefaultRate, timeoutMs: DefaultTimeoutMs}
	if c.Ports != "" {
		ps, err := parsePorts(c.Ports)
		if err != nil {
			return settings{}, tool.Invalid("svcdetect: ports: %v", err)
		}
		s.ports = ps
	}
	for _, t := range c.Transports {
		switch strings.ToLower(t) {
		case "tcp":
		case "udp":
			s.udp = true
		default:
			return settings{}, tool.Invalid("svcdetect: unknown transport (tcp or udp)")
		}
	}
	switch c.Depth {
	case "", DepthFast:
	case DepthThorough:
		s.thorough = true
	default:
		return settings{}, tool.Invalid("svcdetect: unknown depth (fast or thorough)")
	}
	if c.Rate > 0 {
		s.rate = min(c.Rate, MaxRate)
	}
	if c.TimeoutMs > 0 {
		s.timeoutMs = min(max(c.TimeoutMs, MinTimeoutMs), MaxTimeoutMs)
	}
	return s, nil
}

// portSet is a parsed port list (nil: every port).
type portSet [][2]int

func parsePorts(v string) (portSet, error) {
	var out portSet
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := atoiPort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = atoiPort(hi); err != nil {
				return nil, err
			}
		}
		if b < a {
			return nil, fmt.Errorf("range %d-%d is reversed", a, b)
		}
		out = append(out, [2]int{a, b})
		if len(out) > 1024 {
			return nil, errors.New("too many ranges")
		}
	}
	return out, nil
}

func atoiPort(s string) (int, error) {
	n := 0
	if s == "" || len(s) > 5 {
		return 0, errors.New("not a port")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not a port")
		}
		n = n*10 + int(r-'0')
	}
	if n < 1 || n > 65535 {
		return 0, errors.New("port outside 1-65535")
	}
	return n, nil
}

// has reports whether the set allows port (a nil set allows every port).
func (p portSet) has(port int) bool {
	return p == nil || slices.ContainsFunc(p, func(r [2]int) bool { return port >= r[0] && port <= r[1] })
}
