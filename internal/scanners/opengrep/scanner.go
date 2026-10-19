// Package opengrep runs opengrep (https://github.com/opengrep/opengrep), the
// SAST engine of the sast.code capability, over a source tree.
//
// opengrep runs local rules only: the managed rules pack (internal/content,
// the semgrep-rules content, which opengrep reads unchanged), the
// platform's custom rules of a scan, or rule paths the operator sets.
// Registry rule names ("auto", "p/...", URLs) are refused before the run,
// and the tool has no network (tool.yaml), so rules are never fetched on
// anyone's behalf and the engine cannot send anything out.
package opengrep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"

	"github.com/openctemio/sensor/internal/scanners/internal/report"
	"github.com/openctemio/sensor/internal/scanners/internal/tenantrules"
	"github.com/openctemio/sensor/internal/toolrun"
)

const (
	// DefaultBinary is the default opengrep binary name.
	DefaultBinary = "opengrep"

	// DefaultOutputFile is the default report file name.
	DefaultOutputFile = "opengrep-report.json"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute
)

// ErrNoRules is returned when a scan has no rules to run: no managed rules
// pack, no custom rules and no configured rule path.
var ErrNoRules = errors.New("opengrep: no rules to run: install the rules pack (managed content semgrep-rules) or configure a local rules path")

// Scanner runs opengrep. Its fields are what the sensor hands the tool
// child (tool.go), so they serialize.
type Scanner struct {
	Binary     string        `json:"binary,omitempty"`      // opengrep binary (default "opengrep")
	OutputFile string        `json:"output_file,omitempty"` // report file: an absolute path is used as is; otherwise the base name, in a temporary directory removed after the scan
	Timeout    time.Duration `json:"timeout,omitempty"`     // scan timeout (default 30 minutes)
	Verbose    bool          `json:"verbose,omitempty"`

	// Configs are local rules files or directories.
	Configs        []string `json:"configs,omitempty"`
	ExcludePaths   []string `json:"exclude_paths,omitempty"`
	IncludePaths   []string `json:"include_paths,omitempty"`
	DataflowTrace  bool     `json:"dataflow_trace,omitempty"`   // taint traces in the report (default true)
	TaintIntrafile bool     `json:"taint_intrafile,omitempty"`  // --taint-intrafile
	RuleTimeout    int      `json:"rule_timeout,omitempty"`     // --timeout, seconds (0: engine default)
	MaxTargetBytes int64    `json:"max_target_bytes,omitempty"` // --max-target-bytes (0: engine default)
	Jobs           int      `json:"jobs,omitempty"`             // --jobs (0: engine default)
	MaxMemory      int      `json:"max_memory,omitempty"`       // --max-memory, MiB (0: no limit)
	NoGitIgnore    bool     `json:"no_git_ignore,omitempty"`

	version string
}

// NewScanner returns an opengrep scanner with the defaults.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:        DefaultBinary,
		OutputFile:    DefaultOutputFile,
		Timeout:       DefaultTimeout,
		DataflowTrace: true,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string { return "opengrep" }

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType { return core.ScannerTypeSAST }

// Version returns the scanner version.
func (s *Scanner) Version() string { return s.version }

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	return []string{"sast", "code_analysis", "vulnerability_detection", "code_quality", "taint_tracking"}
}

// IsInstalled checks that the opengrep binary runs.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	installed, version, err := core.CheckBinaryInstalled(ctx, s.binary(), "--version")
	if err != nil {
		return false, "", err
	}
	if installed {
		s.version = version
	}
	return installed, version, nil
}

// SetVerbose enables or disables verbose output.
func (s *Scanner) SetVerbose(v bool) { s.Verbose = v }

func (s *Scanner) binary() string {
	if s.Binary == "" {
		return DefaultBinary
	}
	return s.Binary
}

// Scan runs opengrep on the target.
//
// The scan runs out of process, in the task sandbox (tool.go), unless
// SENSOR_TOOL_RUNTIME=in-process.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	ctx, opts, jobErr := toolrun.ApplyJob(ctx, ToolManifest, settingsSchema, opts)
	if jobErr != nil {
		return nil, jobErr
	}
	sc, err := s.forScan(opts)
	if err != nil {
		return nil, err
	}
	if toolrun.OutOfProcess() {
		return sc.outOfProcess(ctx, target, opts)
	}
	return sc.scanDirect(ctx, target, opts)
}

// scanDirect is the direct path: opengrep runs as this process's child.
func (s *Scanner) scanDirect(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	// The organization's rules run as a copy whose ids the report maps
	// back to tenant:-prefixed ids (tenantrules).
	opts, tenant, cleanupRules, err := tenantrules.ForScan(opts)
	if err != nil {
		return nil, err
	}
	defer cleanupRules()
	configs, err := s.ruleConfigs(opts)
	if err != nil {
		return nil, err
	}

	// The report never goes into the scanned tree (it may be read-only):
	// a relative OutputFile lands in a private temporary directory.
	outputFile, cleanupReport, err := report.Path(s.OutputFile, DefaultOutputFile, "opengrep")
	if err != nil {
		return nil, err
	}
	defer cleanupReport()
	args := s.buildArgs(absTarget, outputFile, configs, opts)
	if s.Verbose {
		fmt.Printf("[opengrep] Command: %s %s\n", s.binary(), strings.Join(args, " "))
	}

	env := map[string]string{
		// opengrep keeps its log and settings in $XDG_CONFIG_HOME/.opengrep:
		// the report's private directory, the only place the sandbox lets
		// it write.
		"XDG_CONFIG_HOME": filepath.Dir(outputFile),
	}
	if opts != nil {
		for k, v := range opts.Env {
			env[k] = v
		}
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:     s.binary(),
		Args:       args,
		WorkDir:    absTarget,
		Timeout:    timeout,
		Verbose:    s.Verbose,
		Env:        env,
		WritePaths: []string{filepath.Dir(outputFile)},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute opengrep: %w", err)
	}
	// 0: success; 1: findings with --error (not passed); 2 and above: an
	// error (bad rules, bad target, out of memory).
	if execResult.ExitCode > 1 {
		return nil, fmt.Errorf("opengrep exited with code %d: %s", execResult.ExitCode, lastLines(string(execResult.Stderr), 8))
	}
	outputData, err := os.ReadFile(outputFile) // #nosec G304 -- the scanner's own report path
	if err != nil {
		return nil, fmt.Errorf("failed to read opengrep output: %w", err)
	}
	_ = os.Remove(outputFile)
	return &core.ScanResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		ExitCode:       execResult.ExitCode,
		RawOutput:      tenant.RestoreReport(outputData),
		Stderr:         string(execResult.Stderr),
	}, nil
}

// ruleConfigs returns the local rules of a scan: the platform's custom
// rules of the scan and the scanner's configured rules (the managed pack),
// each an existing file or directory. A registry name or a URL is refused:
// opengrep would fetch it from a rules registry.
func (s *Scanner) ruleConfigs(opts *core.ScanOptions) ([]string, error) {
	// The job's rule sources (api RFC-118): the organization's rules, the
	// platform's, or both in this one run.
	custom := ""
	if opts != nil {
		custom = opts.CustomTemplateDir
	}
	platform := s.Configs
	if opts != nil && opts.ConfigFile != "" {
		platform = []string{opts.ConfigFile}
	}
	in, err := tenantrules.Select(opts, custom, platform)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		p, err := localRules(c)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, ErrNoRules
	}
	return out, nil
}

// localRules resolves a rules path, refusing anything that is not an
// existing local file or directory.
func localRules(c string) (string, error) {
	c = strings.TrimSpace(c)
	if c == "" || c == "auto" || strings.HasPrefix(c, "-") || strings.Contains(c, "://") {
		return "", fmt.Errorf("opengrep rules %q: only local rules files or directories are run", c)
	}
	p, err := filepath.Abs(c)
	if err != nil {
		return "", fmt.Errorf("opengrep rules %q: %w", c, err)
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("opengrep rules %q: not a local rules file or directory (registry rules are not fetched)", c)
	}
	return p, nil
}

// DefaultExcludes are the paths every scan skips.
var DefaultExcludes = []string{"node_modules", "build", "dist", "vendor", ".env", ".venv", ".tox",
	"*.min.js", ".npm", ".yarn", "test", "tests", "*_test.go"}

// buildArgs builds the opengrep command line.
func (s *Scanner) buildArgs(target, outputFile string, configs []string, opts *core.ScanOptions) []string {
	args := []string{
		"scan",
		"--json",
		"--output", outputFile,
		// Rule ids as the rules write them: the finding identity holds the
		// rule id, so it must not depend on where the rules are installed.
		"--no-rewrite-rule-ids",
		"--disable-version-check",
		// An inline ignore comment or a .semgrepignore in the scanned tree is
		// the author's claim, not a decision: report the results and let the
		// platform decide (known false positives are decided there).
		"--disable-nosem",
		"--x-ignore-semgrepignore-files",
	}
	if s.DataflowTrace {
		args = append(args, "--dataflow-traces")
	}
	if s.TaintIntrafile {
		args = append(args, "--taint-intrafile")
	}
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	// The paths an absent ignore file would skip, now that the tree's own
	// ignore file is not read: dependencies, build output, tests.
	excludes := append(append([]string{}, DefaultExcludes...), s.ExcludePaths...)
	includes := s.IncludePaths
	if opts != nil {
		excludes = append(append([]string{}, excludes...), opts.Exclude...)
		includes = append(append([]string{}, includes...), opts.Include...)
	}
	for _, e := range excludes {
		args = append(args, "--exclude", e)
	}
	for _, i := range includes {
		args = append(args, "--include", i)
	}
	if s.RuleTimeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(s.RuleTimeout))
	}
	if s.MaxTargetBytes > 0 {
		args = append(args, "--max-target-bytes", strconv.FormatInt(s.MaxTargetBytes, 10))
	}
	if s.Jobs > 0 {
		args = append(args, "--jobs", strconv.Itoa(s.Jobs))
	}
	if s.MaxMemory > 0 {
		args = append(args, "--max-memory", strconv.Itoa(s.MaxMemory))
	}
	if s.NoGitIgnore {
		args = append(args, "--no-git-ignore")
	}
	if s.Verbose {
		args = append(args, "--verbose")
	}
	if opts != nil {
		args = append(args, opts.ExtraArgs...)
	}
	return append(args, target)
}

// lastLines returns at most n trailing lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
