package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// The recon tools as tools of the tool contract (sdk-go pkg/tool). The
// scanner (Scanner, dispatched as before) runs each scan of a ported tool
// out of process: the sensor re-executes itself as
// "<sensor> __openctem-tool <name>" in the task sandbox and the tool runs
// the same direct path there. Its output is the same CTIS report, checked
// and stamped by the runtime. Each ported tool has its manifest in
// tool_<name>.go.

// versionedRecon is a recon tool whose version the parent hands its child
// (found by IsInstalled in the parent, never re-probed in the child).
type versionedRecon interface {
	core.ReconScanner
	SetVersion(v string)
}

// reconPort is one recon tool ported to the tool contract.
type reconPort struct {
	manifest tool.Manifest
	tool     tool.Tool
	// matches reports whether a recon scanner is this tool's own type (a
	// test double that only borrows the name is not ported).
	matches func(core.ReconScanner) bool
	// decode rebuilds the configured scanner in the tool child.
	decode func(raw json.RawMessage, version string) (core.ReconScanner, error)
}

// ports are the ported recon tools, by name.
var ports = map[string]*reconPort{}

// portRecon registers the recon tool of type P under its manifest: the tool
// child serves it and the scanner of that type runs out of process.
func portRecon[T any, P interface {
	*T
	versionedRecon
}](m tool.Manifest) tool.Tool {
	p := &reconPort{
		manifest: m,
		matches:  func(rs core.ReconScanner) bool { _, ok := rs.(P); return ok },
		decode: func(raw json.RawMessage, version string) (core.ReconScanner, error) {
			s := P(new(T))
			if err := json.Unmarshal(raw, s); err != nil {
				return nil, err
			}
			s.SetVersion(version)
			return s, nil
		},
	}
	// A tool with a configuration schema (the one scans are validated
	// against) gets its settings applied by the sensor before the child
	// starts: the child ignores the task's configuration either way.
	if len(m.Config) > 0 {
		p.tool = tool.New(m, func(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
			return runReconTool(ctx, task, p)
		})
	} else {
		p.tool = tool.New(m, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
			return runReconTool(ctx, task, p)
		})
	}
	toolrun.Register(p.tool)
	ports[m.Name] = p
	return p.tool
}

// reconLocal is what the sensor hands its recon child: the configured tool
// (settings of the scan already applied), the scanner's options with the
// sensor's resolvers, and the scan's lowered limits; never platform input
// beyond the admitted targets.
type reconLocal struct {
	Scanner json.RawMessage   `json:"scanner"`
	Version string            `json:"version,omitempty"`
	Options core.ReconOptions `json:"options"`
	Scan    scanLocal         `json:"scan"`
}

// scanLocal is the part of core.ScanOptions a recon run uses.
type scanLocal struct {
	ExtraArgs   []string          `json:"extra_args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	RateLimit   int               `json:"rate_limit,omitempty"`
	Concurrency int               `json:"concurrency,omitempty"`
	Verbose     bool              `json:"verbose,omitempty"`
}

func scanLocalOf(opts *core.ScanOptions) scanLocal {
	if opts == nil {
		return scanLocal{}
	}
	return scanLocal{ExtraArgs: opts.ExtraArgs, Env: opts.Env, RateLimit: opts.RateLimit, Concurrency: opts.Concurrency, Verbose: opts.Verbose}
}

func (l scanLocal) options() *core.ScanOptions {
	return &core.ScanOptions{ExtraArgs: l.ExtraArgs, Env: l.Env, RateLimit: l.RateLimit, Concurrency: l.Concurrency, Verbose: l.Verbose}
}

// port returns the scanner's tool when it is ported (nil otherwise).
func (s *Scanner) port() *reconPort {
	p := ports[s.recon.Name()]
	if p == nil || !p.matches(s.recon) {
		return nil
	}
	return p
}

// outOfProcess runs a ported tool's scan in the tool child (ran false when
// the tool is not ported or the out-of-process path is off).
func (s *Scanner) outOfProcess(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, bool, error) {
	p := s.port()
	if p == nil || !toolrun.OutOfProcess() {
		return nil, false, nil
	}
	// The scan's settings are applied here, to a copy of the tool: the
	// child receives the configured tool, never the raw settings.
	rs, err := s.forScan(opts)
	if err != nil {
		return nil, true, err
	}
	// The sandbox grants no capabilities: a scan that needs raw sockets (a
	// naabu SYN scan, which the sensor never configures by default) stays
	// on the direct path.
	if r, ok := rs.(interface{ RawSockets() bool }); ok && r.RawSockets() {
		return nil, false, nil
	}
	if err := checkHostBoundArgs(s.Options.ExtraArgs); err != nil {
		return nil, true, err
	}
	if opts != nil {
		if err := checkHostBoundArgs(opts.ExtraArgs); err != nil {
			return nil, true, err
		}
	}
	ro := s.Options
	// The sensor's resolvers are read here (SENSOR_DNS_RESOLVERS does not
	// reach the child's environment), as the direct path reads them.
	if len(ro.Resolvers) == 0 && slices.Contains(resolvingTools, rs.Name()) {
		r, err := sensorResolvers(nil)
		if err != nil {
			return nil, true, err
		}
		ro.Resolvers = r
	}
	raw, err := json.Marshal(rs)
	if err != nil {
		return nil, true, fmt.Errorf("%s: encode the tool: %w", rs.Name(), err)
	}
	local := reconLocal{Scanner: raw, Version: rs.Version(), Options: ro, Scan: scanLocalOf(opts)}
	res, _, err := toolrun.Run(ctx, p.tool, targets, local, toolhost.RunOptions{})
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil, true, ctx.Err()
		}
		return nil, true, fmt.Errorf("%w: %w", ErrToolFailed, err)
	}
	return res, true, nil
}

// runReconTool is a ported recon tool's Run in the tool child: the
// scanner's direct path, its report emitted record by record, and each
// target's outcome.
func runReconTool(ctx tool.Context, task tool.Task, p *reconPort) error {
	name := p.manifest.Name
	var local reconLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || len(local.Scanner) == 0 {
		return tool.Invalid("%s: the sensor's task configuration is missing or unreadable", name)
	}
	rs, err := p.decode(local.Scanner, local.Version)
	if err != nil {
		return tool.Invalid("%s: the sensor's tool configuration is unreadable", name)
	}
	s := NewScanner(rs)
	s.Options = local.Options
	values := make([]string, len(task.Targets))
	for i, t := range task.Targets {
		values[i] = t.Value
	}
	res, err := s.scanTargets(ctx, values, local.Scan.options())
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(err)
	}
	var report ctis.Report
	if err := json.Unmarshal(res.RawOutput, &report); err != nil {
		return tool.Failed(fmt.Errorf("%s report: %w", name, err))
	}
	failed := map[string]string{}
	if ft, ok := report.Properties["failed_targets"]; ok {
		b, _ := json.Marshal(ft)
		var list []failedTarget
		_ = json.Unmarshal(b, &list)
		for _, f := range list {
			failed[f.Target] = f.Error
		}
	}
	if err := ctx.Emit().Report(&report); err != nil {
		if errors.Is(err, tool.ErrOutputLimit) {
			return err
		}
		ctx.Log().Warn(name+": a record was refused", "error", err.Error())
	}
	for _, t := range task.Targets {
		if msg, bad := failed[t.Value]; bad {
			ctx.TargetError(t, tool.Unreachable(errors.New(msg)))
			continue
		}
		ctx.TargetDone(t)
	}
	return nil
}

// ToolContract names the tool manifest of a ported recon tool in the
// sensor manifest (nil for the others).
func (s *Scanner) ToolContract() *core.ToolContract {
	if p := s.port(); p != nil {
		return p.manifest.Contract()
	}
	return nil
}
