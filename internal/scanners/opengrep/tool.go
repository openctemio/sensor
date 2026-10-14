package opengrep

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/toolrun"
)

// opengrep as a tool of the tool contract (sdk-go pkg/tool). The scanner
// runs each scan out of process: the sensor re-executes itself as
// "<sensor> __openctem-tool opengrep" in the task sandbox (no network,
// scan roots read-only) and the direct path runs there. The JSON report
// comes back as the task's raw output (toolrun.RunRaw) and is parsed by
// the sensor with the command's parse options.

// ToolManifest describes the opengrep tool.
var ToolManifest = toolrun.MustManifest(ToolYAML)

// Tool runs opengrep in the tool child.
var Tool = toolrun.Register(tool.New(ToolManifest, runTool))

// opengrepLocal is what the sensor hands its opengrep child: the scanner
// configured for the scan (settings applied), its version and the scan
// options.
type opengrepLocal struct {
	Scanner *Scanner         `json:"scanner"`
	Version string           `json:"version,omitempty"`
	Scan    core.ScanOptions `json:"scan"`
}

// SetVersion sets the version IsInstalled found (a tool child that did not
// probe the binary itself reports the parent's).
func (s *Scanner) SetVersion(v string) { s.version = v }

// outOfProcess runs one scan in the tool child.
func (s *Scanner) outOfProcess(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	local := opengrepLocal{Scanner: s, Version: s.version}
	if opts != nil {
		local.Scan = *opts
		local.Scan.Settings = nil
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}
	var write []string
	if s.OutputFile != "" && filepath.IsAbs(s.OutputFile) {
		write = append(write, filepath.Dir(s.OutputFile))
	}
	res, _, err := toolrun.RunRaw(ctx, Tool, []string{abs}, local, toolhost.RunOptions{WritePaths: write})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if res.ScannerVersion == "" {
		res.ScannerVersion = s.version
	}
	res.StartedAt, res.FinishedAt = start.Unix(), time.Now().Unix()
	return res, nil
}

// runTool is opengrep's Run in the tool child.
func runTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var local opengrepLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.Scanner == nil {
		return tool.Invalid("opengrep: the sensor's task configuration is missing or unreadable")
	}
	if len(task.Targets) != 1 {
		return tool.Invalid("opengrep: one target per task")
	}
	s := local.Scanner
	s.SetVersion(local.Version)
	res, err := s.scanDirect(ctx, task.Targets[0].Value, &local.Scan)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(err)
	}
	return toolrun.EmitRaw(ctx, task, res)
}

// ToolContract names opengrep's tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(ToolManifest) }
