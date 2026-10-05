package semgrep

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

// semgrep as a tool of the tool contract (sdk-go pkg/tool). The scanner
// runs each scan out of process: the sensor re-executes itself as
// "<sensor> __openctem-tool semgrep" in the task sandbox and the scanner's
// direct path runs there. semgrep's JSON report comes back as the task's
// raw output (toolrun.RunRaw) and is parsed by the sensor with the
// command's parse options (repository, branch, commit, base path), exactly
// as before.
//
// SEMGREP_* settings of the sensor (an app token among them) reach semgrep
// only through the scanner environment allowlist, as on the direct path;
// they are never part of the task.

// ToolManifest describes the semgrep tool.
var ToolManifest = tool.Manifest{
	Name:         "semgrep",
	Version:      "1.0.0",
	Description:  "Static analysis of a source tree with semgrep rules (registry rules or the platform's custom rules).",
	Class:        tool.TargetScan,
	Tier:         tool.T0,
	Capabilities: []string{"sast", "code_analysis", "vulnerability_detection", "code_quality", "taint_tracking"},
	Consumes:     []string{"repository"},
	Produces:     []string{"asset:repository", "finding:vulnerability"},
	Permissions:  tool.Permissions{Network: tool.NetEgressProxy, Filesystem: tool.FSScanRootsReadOnly},
	Resources: tool.Resources{
		Timeout: tool.Duration(6 * time.Hour),
	},
}

// Tool runs semgrep in the tool child.
var Tool = toolrun.Register(tool.New(ToolManifest, runTool))

// semgrepLocal is what the sensor hands its semgrep child: the configured
// scanner, its version and the scan options (no settings: semgrep has
// none).
type semgrepLocal struct {
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
	local := semgrepLocal{Scanner: s, Version: s.version}
	if opts != nil {
		local.Scan = *opts
		local.Scan.Settings = nil
	}
	// The child's working directory is its task directory: a relative
	// path is resolved here, as the direct path resolves it.
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}
	// The child writes only its task directory (the report lands in its
	// private temporary directory), plus an absolute report file the
	// operator configured.
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

// runTool is semgrep's Run in the tool child.
func runTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var local semgrepLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.Scanner == nil {
		return tool.Invalid("semgrep: the sensor's task configuration is missing or unreadable")
	}
	if len(task.Targets) != 1 {
		return tool.Invalid("semgrep: one target per task")
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

// ToolContract names semgrep's tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return ToolManifest.Contract() }
