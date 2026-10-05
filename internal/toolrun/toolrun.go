// Package toolrun runs the sensor's tools that are ported to the tool
// contract (sdk-go pkg/tool) out of process: each scan re-executes the
// sensor as "<sensor> __openctem-tool <name>" inside the task sandbox, and
// the runtime checks and stamps what comes back (sdk-go
// pkg/sensorkit/toolhost). The design is sdk-go docs/rfcs/sensor-sdk-v2.md.
//
// A tool's scanner (core.Scanner, dispatched as before) calls Run; the
// child process runs the same scanner's direct path through the tool's
// Run function. SENSOR_TOOL_RUNTIME=in-process turns the out-of-process
// path off (a rollback switch; the default runs every ported tool out of
// process).
package toolrun

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// EnvRuntime selects how ported tools run: "out-of-process" (default) or
// "in-process" (rollback).
const EnvRuntime = "SENSOR_TOOL_RUNTIME"

var (
	mu   sync.RWMutex
	host = &toolhost.Host{RuntimeName: "openctem-sensor"}
)

// Configure names the sensor in the provenance and sets the logger that
// receives the tools' (redacted) log lines.
func Configure(sensor, version string, logger *slog.Logger) {
	mu.Lock()
	defer mu.Unlock()
	host = &toolhost.Host{RuntimeName: "openctem-sensor", RuntimeVersion: version, Sensor: sensor, Logger: logger}
}

// SetHost replaces the host (tests).
func SetHost(h *toolhost.Host) {
	mu.Lock()
	host = h
	mu.Unlock()
}

// InChild reports whether this process is a tool child (serving a tool),
// where scanners run their direct path.
func InChild() bool { return len(os.Args) > 1 && os.Args[1] == adapter.ToolArg }

// OutOfProcess reports whether ported tools run out of process.
func OutOfProcess() bool {
	if InChild() {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvRuntime))) {
	case "in-process", "inprocess", "legacy", "off":
		return false
	}
	return true
}

// Targets turns scan targets into task targets (refs t0, t1, ...).
func Targets(values []string, assetType string) []tool.Target {
	out := make([]tool.Target, len(values))
	for i, v := range values {
		out[i] = tool.Target{Ref: fmt.Sprintf("t%d", i), Type: assetType, Value: v}
	}
	return out
}

// Run runs one task of t out of process with local (the scanner's own
// configuration, never from the platform) and returns the result as a
// core.ScanResult whose raw output is the checked CTIS report. A task that
// failed returns its categorized error.
func Run(ctx context.Context, t tool.Tool, targets []string, local any, o toolhost.RunOptions) (*core.ScanResult, *toolhost.Outcome, error) {
	raw, err := json.Marshal(local)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: encode the task: %w", t.Manifest().Name, err)
	}
	task := tool.Task{Targets: Targets(targets, ""), Local: raw}
	h, ro := current(o)
	out, err := h.RunBuiltin(ctx, t, task, ro)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", t.Manifest().Name, err)
	}
	if out.Err != nil && out.Status != tool.StatusPartial {
		return nil, out, fmt.Errorf("%s: %w", t.Manifest().Name, out.Err)
	}
	// Targets the local policy refused were never scanned: the report says
	// so, next to the ones that were ("refused_targets").
	if refused := Refused(out); len(refused) > 0 && out.Report != nil {
		list := make([]map[string]string, 0, len(refused))
		for _, r := range refused {
			list = append(list, map[string]string{"target": r.Value, "class": string(r.Class), "error": r.Detail})
		}
		if out.Report.Properties == nil {
			out.Report.Properties = ctis.Properties{}
		}
		out.Report.Properties["refused_targets"] = list
	}
	rep, err := out.ReportJSON()
	if err != nil {
		return nil, out, err
	}
	version := ""
	if out.Report != nil && out.Report.Tool != nil {
		version = out.Report.Tool.Version
	}
	return &core.ScanResult{
		ScannerName:    t.Manifest().Name,
		ScannerVersion: version,
		DurationMs:     out.Duration.Milliseconds(),
		RawOutput:      rep,
		Stderr:         out.Stderr,
	}, out, nil
}

var (
	regMu      sync.Mutex
	registered = map[string]tool.Tool{}
)

// Register adds a ported tool to the sensor's compiled-in tools: the
// tool child serves it ("<sensor> __openctem-tool <name>") and
// `tools manifests` lists it. Each tool's package registers its tool when
// it is initialized, so adding a tool touches only its own package. A
// second tool with the same name is a programming error.
func Register(t tool.Tool) tool.Tool {
	name := t.Manifest().Name
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registered[name]; dup {
		panic("toolrun: tool " + name + " registered twice")
	}
	registered[name] = t
	return t
}

// Registered returns the registered tools, sorted by name.
func Registered() []tool.Tool {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]tool.Tool, 0, len(registered))
	for _, t := range registered {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest().Name < out[j].Manifest().Name })
	return out
}

// RunTask runs one task of t out of process as it is (a retest task, whose
// targets and items the caller built) through the host with the admission
// in force, and returns the outcome as the host reports it.
func RunTask(ctx context.Context, t tool.Tool, task tool.Task, o toolhost.RunOptions) (*toolhost.Outcome, error) {
	h, ro := current(o)
	out, err := h.RunBuiltin(ctx, t, task, ro)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", t.Manifest().Name, err)
	}
	return out, nil
}
