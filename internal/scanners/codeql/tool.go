package codeql

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

// CodeQL as a tool of the tool contract (sdk-go pkg/tool). Each scan runs
// out of process: the sensor re-executes itself as
// "<sensor> __openctem-tool codeql" in the task sandbox and the direct path
// (database creation, then analysis) runs there. The SARIF report comes
// back as the task's raw output (toolrun.RunRaw) and is parsed by the
// sensor with the command's parse options, exactly as before.

// ToolManifest describes the codeql tool.
var ToolManifest = toolrun.MustManifest(ToolYAML)

// ContractTool runs codeql in the tool child (Tool is the SARIF tool type).
var ContractTool = toolrun.Register(tool.New(ToolManifest, runTool))

// codeqlLocal is what the sensor hands its codeql child: the configured
// scanner, its version and the scan options.
type codeqlLocal struct {
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
	local := codeqlLocal{Scanner: s, Version: s.version}
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
	// The child writes its task directory (a per-scan database is built
	// there), plus an operator-configured database and report file.
	var write []string
	switch {
	case s.DatabasePath != "":
		db, err := filepath.Abs(s.DatabasePath)
		if err != nil {
			return nil, fmt.Errorf("resolve the database path: %w", err)
		}
		local.Scanner = s.withDatabase(db)
		write = append(write, db)
	case s.SkipDBCreation:
		write = append(write, filepath.Join(abs, ".codeql-db"))
	}
	if s.OutputFile != "" && filepath.IsAbs(s.OutputFile) {
		write = append(write, filepath.Dir(s.OutputFile))
	}
	res, _, err := toolrun.RunRaw(ctx, ContractTool, []string{abs}, local, toolhost.RunOptions{WritePaths: write})
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

// withDatabase is a copy of the scanner on an absolute database path.
func (s *Scanner) withDatabase(db string) *Scanner {
	c := *s
	c.DatabasePath = db
	return &c
}

// runTool is codeql's Run in the tool child.
func runTool(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var local codeqlLocal
	if err := json.Unmarshal(task.Local, &local); err != nil || local.Scanner == nil {
		return tool.Invalid("codeql: the sensor's task configuration is missing or unreadable")
	}
	if len(task.Targets) != 1 {
		return tool.Invalid("codeql: one target per task")
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

// ToolContract names codeql's tool manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return ToolManifest.Contract() }
