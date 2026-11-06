// Package webguess is the sensor's path discovery tool
// (enumerate.web_paths@1): it requests the candidate paths the platform puts
// in the signed job and reports the ones the calibrated differ (sdk-go
// pkg/webdiff) confirms. It is our own engine, compiled into the sensor and
// run out of process in the task sandbox like the other ported tools.
//
// Safety, on top of the differ's own bounds:
//   - it refuses to start (fail closed) unless the job carries a web scope
//     that allows only GET and HEAD and caps the requests per host; the
//     task forwarder enforces the same scope and cap on every request;
//   - every request goes through the task's tool.Context.HTTP client, so
//     the web scope, the request cap, the address pinning, the pacing and
//     the job's identification apply;
//   - it never adds a path: the candidates are the job's composed list
//     only, filtered with the web scope, the scan's excluded paths and
//     contract webpath.Destructive (counted as scope_filtered); it never
//     recurses, and reports only a path of that list the differ confirmed;
//   - an origin whose first answer is an edge challenge or block is skipped
//     (edge_protected);
//   - it logs counts only, never a candidate or a response.
//
// Each origin's gaps (pkg/webdiff gap reasons) travel to the sensor as the
// run's coverage gaps: the host is the origin, the reason the main one, the
// detail every reason with the number of candidates it concerned.
package webguess

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

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

// Manifest describes the webguess tool.
var Manifest = toolrun.MustManifest(ToolYAML)

// Tool runs webguess in the tool child.
var Tool = toolrun.RegisterCompiledIn(tool.New(Manifest, run))

var settingsSchema = core.MustParseSettingsSchema(string(Manifest.Config))

// Slot is the content slot of the candidate list.
const Slot = "paths"

// Defaults of the configuration (tool.yaml).
const (
	DefaultMaxRequests = 300
	DefaultRate        = 5
)

// Config is the tool's configuration (tool.yaml config), mapped from the
// scan's settings by the sensor and handed to the child in Local.
type Config struct {
	Lists        []string `json:"lists,omitempty"`
	Extensions   string   `json:"extensions,omitempty"`
	MaxRequests  int      `json:"max_requests,omitempty"`
	Rate         int      `json:"rate,omitempty"`
	ExcludePaths []string `json:"exclude_paths,omitempty"`
}

// Scanner runs webguess as a core.Scanner (and MultiTargetScanner,
// CapabilityScanner, ContentScanner, SettingsSchemaProvider,
// ToolContractProvider).
type Scanner struct{}

// NewScanner is the webguess scanner the command executor dispatches.
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

// EnforcesScopeLimits: every request goes through the task's client and,
// on a confined sandbox, its forwarder, which enforce a job's limits.
func (s *Scanner) EnforcesScopeLimits() bool { return true }

// RoutesEgress: the tool runs out of process through the tool host.
func (s *Scanner) RoutesEgress() bool { return true }

// TakesCapabilityJobs: the tool implements enumerate.web_paths@1.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(Manifest) }

// TakesJobContent: the job's candidate list reaches the tool as its
// "paths" slot, composed by the tool host.
func (s *Scanner) TakesJobContent() bool { return true }

// Scan probes one origin.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// ErrExtraArgs: webguess has no command line to add arguments to.
var ErrExtraArgs = errors.New("webguess takes no extra arguments")

// ScanTargets probes every origin in one task.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	ctx, opts, err := toolrun.ApplyJob(ctx, Manifest, settingsSchema, opts)
	if err != nil {
		return nil, err
	}
	cfg := Config{}
	var content []tool.TaskContent
	if opts != nil {
		if len(opts.ExtraArgs) > 0 {
			return nil, fmt.Errorf("webguess: %w", ErrExtraArgs)
		}
		if opts.Settings != nil {
			if opts.Settings.SchemaDigest() != settingsSchema.Digest() {
				return nil, errors.New("webguess settings: resolved against another schema")
			}
			cfg = configFrom(opts.Settings)
		}
		content = toolrun.TaskContent(opts.Content)
	}
	res, _, err := toolrun.RunContent(ctx, Tool, targets, cfg, content, toolhost.RunOptions{})
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
	if v, ok := ts.Strings("lists"); ok {
		c.Lists = v
	}
	if v, ok := ts.String("extensions"); ok {
		c.Extensions = v
	}
	if v, ok := ts.Int("max_requests"); ok {
		c.MaxRequests = int(v)
	}
	if v, ok := ts.Int("rate"); ok {
		c.Rate = int(v)
	}
	if v, ok := ts.Strings("exclude_paths"); ok {
		c.ExcludePaths = v
	}
	return c
}

// readConfig decodes the child's configuration and fills the defaults.
func readConfig(task tool.Task) (Config, error) {
	var c Config
	if len(task.Local) > 0 {
		if err := json.Unmarshal(task.Local, &c); err != nil {
			return c, tool.Invalid("webguess: the sensor's task configuration is unreadable")
		}
	}
	if c.MaxRequests <= 0 {
		c.MaxRequests = DefaultMaxRequests
	}
	c.MaxRequests = min(c.MaxRequests, 100000)
	if c.Rate <= 0 {
		c.Rate = DefaultRate
	}
	c.Rate = min(c.Rate, 50)
	for _, p := range c.ExcludePaths {
		if p == "" || p[0] != '/' {
			return c, tool.Invalid("webguess: an excluded path must start with /")
		}
	}
	if slices.ContainsFunc(c.Lists, func(l string) bool { return !slices.Contains([]string{"derived", "s", "m", "l"}, l) }) {
		return c, tool.Invalid("webguess: unknown candidate list")
	}
	return c, nil
}
