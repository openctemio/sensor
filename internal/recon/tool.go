package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/toolrun"
)

// httpx as a tool of the tool contract (sdk-go pkg/tool). The scanner
// (Scanner, dispatched as before) runs each scan out of process: the sensor
// re-executes itself as "<sensor> __openctem-tool httpx" in the task
// sandbox and HTTPXTool runs the same direct path there. Its output is the
// same CTIS report, checked and stamped by the runtime.

// HTTPXManifest describes the httpx tool.
var HTTPXManifest = tool.Manifest{
	Name:         "httpx",
	Version:      "1.0.0",
	Description:  "HTTP probe: live web services, titles, servers, technologies, TLS leaf certificates (ProjectDiscovery httpx).",
	Class:        tool.TargetScan,
	Tier:         tool.T1,
	Capabilities: []string{"recon", "http", "tech_detect"},
	Consumes:     []string{"domain", "subdomain", "ip_address", "host", "http_service", "open_port", "service", "website"},
	Produces:     []string{"asset:http_service", "asset:certificate"},
	Permissions:  tool.Permissions{Network: tool.NetTargets},
	Resources: tool.Resources{
		Timeout:        tool.Duration(24 * 60 * 60 * 1e9),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1000000,
	},
}

// HTTPXTool runs httpx in the tool child.
var HTTPXTool = tool.New(HTTPXManifest, runHTTPXTool)

// reconLocal is what the sensor hands its recon child: the tool's own
// configuration and the scan's lowered limits, never platform input
// beyond the admitted targets.
type reconLocal struct {
	HTTPX   *httpx.Scanner    `json:"httpx,omitempty"`
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

// outOfProcess runs a ported tool's scan in the tool child (nil when the
// tool is not ported or the out-of-process path is off).
func (s *Scanner) outOfProcess(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, bool, error) {
	hx, ok := s.recon.(*httpx.Scanner)
	if !ok || !toolrun.OutOfProcess() {
		return nil, false, nil
	}
	if opts != nil && opts.Settings != nil {
		return nil, true, fmt.Errorf("%s takes no settings", s.recon.Name())
	}
	if err := checkHostBoundArgs(s.Options.ExtraArgs); err != nil {
		return nil, true, err
	}
	if opts != nil {
		if err := checkHostBoundArgs(opts.ExtraArgs); err != nil {
			return nil, true, err
		}
	}
	local := reconLocal{HTTPX: hx, Version: hx.Version(), Options: s.Options, Scan: scanLocalOf(opts)}
	res, _, err := toolrun.Run(ctx, HTTPXTool, targets, local, toolhost.RunOptions{})
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil, true, ctx.Err()
		}
		return nil, true, fmt.Errorf("%w: %w", ErrToolFailed, err)
	}
	return res, true, nil
}

// runHTTPXTool is httpx's Run in the tool child: the scanner's direct
// path, its report emitted record by record, and each target's outcome.
func runHTTPXTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var local reconLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.HTTPX == nil {
		return tool.Invalid("httpx: the sensor's task configuration is missing or unreadable")
	}
	local.HTTPX.SetVersion(local.Version)
	s := NewScanner(local.HTTPX)
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
		return tool.Failed(fmt.Errorf("httpx report: %w", err))
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
		ctx.Log().Warn("httpx: a record was refused", "error", err.Error())
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
	if _, ok := s.recon.(*httpx.Scanner); ok {
		return HTTPXManifest.Contract()
	}
	return nil
}
