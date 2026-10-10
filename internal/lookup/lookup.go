// Package lookup runs the passive lookup tools (rdap, asn): T0 tools that
// ask public registries and datasets about a target and never send a packet
// to the target hosts (openctem RFC-071, passive discovery).
//
// Each tool is a tool of the tool contract (sdk-go pkg/tool) compiled into
// the sensor and run out of process in the task sandbox, like the recon
// tools. Scanner is the core.Scanner the command executor dispatches: it
// maps a scan's settings to the tool's configuration, hands it to the child
// with the shared cache directory and returns the child's checked CTIS
// report as its raw output.
package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Local is what the sensor hands a lookup tool's child: never from the
// platform.
type Local struct {
	// Config is the tool's configuration (its tool.yaml config), mapped
	// from the scan's settings by the sensor.
	Config json.RawMessage `json:"config,omitempty"`
	// CacheDir holds the public data a lookup reuses across tasks (the
	// IANA bootstrap files, the routing dataset). Never per-target
	// answers: one tenant's lookups leave nothing another task can see.
	// Empty: no cache, the task fetches into its own directory.
	CacheDir string `json:"cache_dir,omitempty"`
}

// ReadLocal decodes the task's local configuration in the child.
func ReadLocal(task tool.Task) (Local, error) {
	var l Local
	if len(task.Local) == 0 {
		return l, nil
	}
	if err := json.Unmarshal(task.Local, &l); err != nil {
		return l, tool.Invalid("the sensor's task configuration is unreadable")
	}
	return l, nil
}

// Spec describes one lookup tool.
type Spec struct {
	Tool   tool.Tool
	Schema *core.SettingsSchema
	// Config maps a scan's settings (already checked against Schema) to
	// the tool's configuration.
	Config func(*core.ToolSettings) (json.RawMessage, error)
}

// Scanner runs a lookup tool as a core.Scanner (and MultiTargetScanner,
// CapabilityScanner, SettingsSchemaProvider, ToolContractProvider).
type Scanner struct {
	spec Spec
	// CacheRoot overrides where the cache lives (tests); empty: the
	// sensor's state directory.
	CacheRoot string
}

// New returns the scanner of a lookup tool.
func New(spec Spec) *Scanner { return &Scanner{spec: spec} }

func (s *Scanner) manifest() tool.Manifest { return s.spec.Tool.Manifest() }

// Name is the tool's name.
func (s *Scanner) Name() string { return s.manifest().Name }

// Version is the tool's version (compiled in).
func (s *Scanner) Version() string { return s.manifest().Version }

// Capabilities are the registry words of the tool; the capabilities it
// implements come from its contract (ToolContract).
func (s *Scanner) Capabilities() []string { return []string{"recon"} }

// IsInstalled: a compiled-in tool is always there.
func (s *Scanner) IsInstalled(context.Context) (bool, string, error) {
	return true, s.Version(), nil
}

// SettingsSchema is the tool's configuration schema.
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return s.spec.Schema }

// ToolContract names the tool's manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(s.manifest()) }

// TakesCapabilityJobs: the tool implements its capability.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(s.manifest()) }

// Scan looks up one target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// ErrExtraArgs: a lookup tool has no command line to add arguments to.
var ErrExtraArgs = errors.New("lookup tools take no extra arguments")

// ScanTargets looks up every target in one task.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	m := s.manifest()
	ctx, opts, err := toolrun.ApplyJob(ctx, m, s.spec.Schema, opts)
	if err != nil {
		return nil, err
	}
	local := Local{}
	if opts != nil {
		if len(opts.ExtraArgs) > 0 {
			return nil, fmt.Errorf("%s: %w", m.Name, ErrExtraArgs)
		}
		if opts.Settings != nil {
			if opts.Settings.SchemaDigest() != s.spec.Schema.Digest() {
				return nil, fmt.Errorf("%s settings: resolved against another schema", m.Name)
			}
			if local.Config, err = s.spec.Config(opts.Settings); err != nil {
				return nil, fmt.Errorf("%s settings: %w", m.Name, err)
			}
		}
	}
	var write []string
	if dir := s.cacheDir(); dir != "" {
		local.CacheDir = dir
		write = append(write, dir)
	}
	res, _, err := toolrun.Run(ctx, s.spec.Tool, targets, local, toolhost.RunOptions{WritePaths: write})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return res, nil
}

// cacheDir is the tool's cache under the sensor's state directory, created
// 0700; "" when it cannot be created (the child then fetches per task).
func (s *Scanner) cacheDir() string {
	root := s.CacheRoot
	if root == "" {
		root = filepath.Join(sensorkit.ResolveStateDir(os.Getenv(sensorkit.EnvStateDir)), "lookup-cache")
	}
	dir := filepath.Join(root, s.Name())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	return dir
}
