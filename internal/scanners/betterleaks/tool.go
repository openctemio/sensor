package betterleaks

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

// betterleaks as a tool of the tool contract (sdk-go pkg/tool). A
// dispatched scan (GenericScan) runs out of process: the sensor re-executes
// itself as "<sensor> __openctem-tool betterleaks" in the task sandbox and
// the direct path runs there. The JSON report comes back as the task's raw
// output (toolrun.RunRaw) and is parsed by the sensor with the command's
// parse options (the repository it files findings on), exactly as before.
//
// The report holds the raw secrets betterleaks found (the parser masks
// them): it travels as an artifact in the task's private directory, which
// the runtime removes with the task, as the direct path's temporary report.

// ToolManifest describes the betterleaks tool.
var ToolManifest = tool.Manifest{
	Name:         "betterleaks",
	Version:      "1.0.0",
	Description:  "Secret detection in a source tree (betterleaks v1, gitleaks-compatible rules).",
	Class:        tool.TargetScan,
	Tier:         tool.T0,
	Capabilities: []string{"secret_detection", "api_key_detection", "password_detection", "private_key_detection"},
	Consumes:     []string{"repository"},
	Produces:     []string{"asset:repository", "finding:secret"},
	Permissions:  tool.Permissions{Network: tool.NetNone, Filesystem: tool.FSScanRootsReadOnly},
	Resources: tool.Resources{
		Timeout: tool.Duration(3 * time.Hour),
	},
}

// Tool runs betterleaks in the tool child.
var Tool = toolrun.Register(tool.New(ToolManifest, runTool))

// betterleaksLocal is what the sensor hands its betterleaks child: the
// configured scanner, its version and the scan options.
type betterleaksLocal struct {
	Scanner *Scanner         `json:"scanner"`
	Version string           `json:"version,omitempty"`
	Scan    core.ScanOptions `json:"scan"`
}

// SetVersion sets the version IsInstalled found (a tool child that did not
// probe the binary itself reports the parent's).
func (s *Scanner) SetVersion(v string) { s.version = v }

// outOfProcess runs one dispatched scan in the tool child.
func (s *Scanner) outOfProcess(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	local := betterleaksLocal{Scanner: s, Version: s.version}
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

// runTool is betterleaks' Run in the tool child.
func runTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var local betterleaksLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.Scanner == nil {
		return tool.Invalid("betterleaks: the sensor's task configuration is missing or unreadable")
	}
	if len(task.Targets) != 1 {
		return tool.Invalid("betterleaks: one target per task")
	}
	s := local.Scanner
	s.SetVersion(local.Version)
	res, err := s.genericScanDirect(ctx, task.Targets[0].Value, &local.Scan)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(err)
	}
	return toolrun.EmitRaw(ctx, task, res)
}

// ToolContract names betterleaks' tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return ToolManifest.Contract() }
