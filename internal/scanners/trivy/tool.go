package trivy

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

// trivy as a tool of the tool contract (sdk-go pkg/tool). The scanner
// (Scanner, dispatched as before under its configured names: trivy-fs,
// trivy-config, trivy-image, ...) runs each scan out of process: the
// sensor re-executes itself as "<sensor> __openctem-tool trivy" in the task
// sandbox and the scanner's direct path runs there. trivy's JSON comes back
// as the task's raw output (toolrun.RunRaw) and is parsed by the sensor with
// the command's parse options, exactly as before: the asset, branch and
// commit a finding is filed on come from the command, which the child
// never sees.
//
// Registry credentials (TRIVY_USERNAME / TRIVY_PASSWORD) reach trivy only
// through the scanner environment allowlist, as on the direct path; they
// are never part of the task.

// ToolManifest describes the trivy tool.
var ToolManifest = toolrun.MustManifest(ToolYAML)

// Tool runs trivy in the tool child.
var Tool = toolrun.Register(tool.New(ToolManifest, runTool))

// trivyLocal is what the sensor hands its trivy child: the configured
// scanner, its version and the scan options (no settings: trivy has none).
type trivyLocal struct {
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
	local := trivyLocal{Scanner: s, Version: s.version}
	if opts != nil {
		local.Scan = *opts
		local.Scan.Settings = nil
	}
	// The child writes only its task directory, plus trivy's shared cache
	// and an absolute output file when the operator configured them.
	var write []string
	if s.CacheDir != "" {
		write = append(write, s.CacheDir)
	}
	if s.OutputFile != "" && filepath.IsAbs(s.OutputFile) {
		write = append(write, filepath.Dir(s.OutputFile))
	}
	// The child's working directory is its task directory: a relative path
	// is resolved here, as the direct path resolves it.
	if s.Mode == ScanModeFS || s.Mode == ScanModeConfig || s.Mode == ScanModeRepo {
		abs, err := filepath.Abs(target)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve target path: %w", err)
		}
		target = abs
	}
	res, _, err := toolrun.RunRaw(ctx, Tool, []string{target}, local, toolhost.RunOptions{WritePaths: write})
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

// runTool is trivy's Run in the tool child.
func runTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var local trivyLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.Scanner == nil {
		return tool.Invalid("trivy: the sensor's task configuration is missing or unreadable")
	}
	if len(task.Targets) != 1 {
		return tool.Invalid("trivy: one target per task")
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

// ToolContract names trivy's tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(ToolManifest) }
