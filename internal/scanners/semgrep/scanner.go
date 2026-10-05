package semgrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
	"github.com/openctemio/sensor/internal/scanners/internal/report"
)

const (
	// DefaultBinary is the default semgrep binary name.
	DefaultBinary = "semgrep"

	// DefaultOutputFile is the default output file name.
	DefaultOutputFile = "semgrep-report.json"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute

	// DefaultConfig is the default semgrep config.
	DefaultConfig = "auto"
)

// Scanner implements the SAST scanner interface for semgrep.
type Scanner struct {
	// Configuration
	Binary     string        // Path to semgrep binary (default: "semgrep")
	OutputFile string        // Report file: an absolute path is used as is; otherwise the base name, in a temporary directory removed after the scan
	Timeout    time.Duration // Scan timeout (default: 30 minutes)
	Verbose    bool          // Enable verbose output

	// Semgrep-specific options
	Configs       []string // Config files or registries (default: ["auto"])
	Severities    []string // Filter by severity: ERROR, WARNING, INFO
	ExcludePaths  []string // Paths to exclude
	IncludePaths  []string // Paths to include
	ProEngine     bool     // Use Semgrep Pro engine
	DataflowTrace bool     // Enable dataflow traces (default: true)
	MaxMemory     int      // Max memory in MB (0 = no limit)
	Jobs          int      // Number of parallel jobs (0 = auto)
	NoGitIgnore   bool     // Don't respect .gitignore

	// Internal
	version string
}

// NewScanner creates a new semgrep scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:        DefaultBinary,
		OutputFile:    DefaultOutputFile,
		Timeout:       DefaultTimeout,
		Configs:       []string{DefaultConfig},
		DataflowTrace: true,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "semgrep"
}

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType {
	return core.ScannerTypeSAST
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	caps := []string{
		"sast",
		"code_analysis",
		"vulnerability_detection",
		"code_quality",
		"taint_tracking",
	}
	if s.ProEngine {
		caps = append(caps, "cross_file_analysis", "secrets_detection", "supply_chain")
	}
	return caps
}

// IsInstalled checks if semgrep is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	installed, version, err := core.CheckBinaryInstalled(ctx, binary, "--version")
	if err != nil {
		return false, "", err
	}

	if installed {
		s.version = version
	}

	return installed, version, nil
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// ScanOptions contains options for a semgrep scan.
type ScanOptions struct {
	// Target directory or files
	TargetDir string

	// Files to scan (for changed-file-only strategy)
	ChangedFiles []string

	// Extra arguments to pass to semgrep
	ExtraArgs []string

	// Environment variables
	Env map[string]string
}

// Scan performs a semgrep scan on the target.
//
// The scan runs out of process, in the task sandbox (tool.go), unless
// SENSOR_TOOL_RUNTIME=in-process.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if toolrun.OutOfProcess() {
		return s.outOfProcess(ctx, target, opts)
	}
	return s.scanDirect(ctx, target, opts)
}

// scanDirect is the direct path: semgrep runs as this process's child.
func (s *Scanner) scanDirect(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()

	// Resolve target path
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}

	// The report never goes into the scanned tree (it may be read-only):
	// a relative OutputFile lands in a private temporary directory.
	outputFile, cleanupReport, err := report.Path(s.OutputFile, DefaultOutputFile, "semgrep")
	if err != nil {
		return nil, err
	}
	defer cleanupReport()

	// Build semgrep arguments
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	args := s.buildArgs(absTarget, outputFile, opts)

	if s.Verbose {
		fmt.Printf("[semgrep] Scanning %s\n", absTarget)
		fmt.Printf("[semgrep] Output: %s\n", outputFile)
		fmt.Printf("[semgrep] Command: %s %s\n", s.Binary, strings.Join(args, " "))
	}

	// Execute semgrep
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Build environment
	env := make(map[string]string)
	if opts != nil && len(opts.Env) > 0 {
		for k, v := range opts.Env {
			env[k] = v
		}
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		WorkDir: absTarget,
		Timeout: timeout,
		Verbose: s.Verbose,
		Env:     env,
		// The tool sandbox lets it write only its report's directory.
		WritePaths: []string{filepath.Dir(outputFile)},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute semgrep: %w", err)
	}

	// Semgrep exit codes:
	// 0 = success, no findings
	// 1 = success, findings exist
	// 2+ = error
	if execResult.ExitCode > 1 {
		return nil, fmt.Errorf("semgrep exited with code %d: %s", execResult.ExitCode, string(execResult.Stderr))
	}

	// Read output file
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read semgrep output: %w", err)
	}

	// Clean up output file
	_ = os.Remove(outputFile)

	result := &core.ScanResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		ExitCode:       execResult.ExitCode,
		RawOutput:      outputData,
		Stderr:         string(execResult.Stderr),
	}

	if s.Verbose {
		fmt.Printf("[semgrep] Scan completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// ScanToFindings performs a scan and returns parsed findings.
func (s *Scanner) ScanToFindings(ctx context.Context, target string, opts *core.ScanOptions) (*SastResult, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	// Parse findings
	return ParseToSastResult(result.RawOutput)
}

// buildArgs builds the semgrep command arguments.
func (s *Scanner) buildArgs(target, outputFile string, opts *core.ScanOptions) []string {
	args := []string{
		"scan",
		"--json",
		"--output", outputFile,
		"--no-rewrite-rule-ids",
		"--disable-version-check",
	}

	// Dataflow traces for taint tracking
	if s.DataflowTrace {
		args = append(args, "--dataflow-traces")
	}

	// Custom templates from ScanOptions take priority (platform-provided templates)
	// For Semgrep, custom templates are YAML rule files passed via --config
	if opts != nil && opts.CustomTemplateDir != "" {
		args = append(args, "--config", opts.CustomTemplateDir)
	}

	// Configs (scanner-level defaults)
	configs := s.Configs
	if opts != nil && opts.ConfigFile != "" {
		configs = []string{opts.ConfigFile}
	}
	// If custom templates were provided, don't use default "auto" config
	// but still use explicitly configured rules
	if opts != nil && opts.CustomTemplateDir != "" && len(configs) == 1 && configs[0] == DefaultConfig {
		configs = nil // Skip default "auto" when using custom templates
	}
	if len(configs) == 0 && (opts == nil || opts.CustomTemplateDir == "") {
		configs = []string{DefaultConfig}
	}
	for _, config := range configs {
		args = append(args, "--config", config)
	}

	// Severities filter
	for _, sev := range s.Severities {
		sev = strings.ToUpper(sev)
		if sev == "ERROR" || sev == "WARNING" || sev == "INFO" {
			args = append(args, "--severity", sev)
		}
	}

	// Exclude paths
	excludes := s.ExcludePaths
	if opts != nil {
		excludes = append(excludes, opts.Exclude...)
	}
	for _, exclude := range excludes {
		args = append(args, "--exclude", exclude)
	}

	// Include paths
	includes := s.IncludePaths
	if opts != nil {
		includes = append(includes, opts.Include...)
	}
	for _, include := range includes {
		args = append(args, "--include", include)
	}

	// Pro engine
	if s.ProEngine {
		args = append(args, "--pro")
	}

	// Memory limit
	if s.MaxMemory > 0 {
		args = append(args, "--max-memory", fmt.Sprintf("%d", s.MaxMemory))
	}

	// Parallel jobs
	if s.Jobs > 0 {
		args = append(args, "--jobs", fmt.Sprintf("%d", s.Jobs))
	}

	// Git ignore
	if s.NoGitIgnore {
		args = append(args, "--no-git-ignore")
	}

	// Verbose
	if s.Verbose {
		args = append(args, "--verbose")
	}

	// Extra args
	if opts != nil {
		args = append(args, opts.ExtraArgs...)
	}

	// Target (last argument)
	args = append(args, target)

	return args
}

// =============================================================================
// SAST Result Types
// =============================================================================

// SastResult holds parsed SAST findings.
type SastResult struct {
	Findings   []SastFinding `json:"findings"`
	DurationMs int64         `json:"duration_ms"`
}

// SastFinding represents a parsed SAST finding.
type SastFinding struct {
	// Identity
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`

	// Description
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`

	// Severity
	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"`

	// Location
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
	Snippet     string `json:"snippet"`

	// Metadata
	CWEs       []string       `json:"cwes,omitempty"`
	References []string       `json:"references,omitempty"`
	DataFlow   []DataFlowStep `json:"data_flow,omitempty"`
	Fix        string         `json:"fix,omitempty"`
}

// DataFlowStep represents a step in the data flow trace.
type DataFlowStep struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Content  string `json:"content"`
	StepType string `json:"step_type"` // source, intermediate, sink
}

// ParseToSastResult parses semgrep JSON output to SastResult.
func ParseToSastResult(data []byte) (*SastResult, error) {
	report, err := ParseJSONBytes(data)
	if err != nil {
		return nil, err
	}

	result := &SastResult{
		Findings: make([]SastFinding, 0, len(report.Results)),
	}

	for _, r := range report.Results {
		finding := SastFinding{
			RuleID:      r.CheckID,
			Fingerprint: r.Extra.Fingerprint,
			Title:       fmt.Sprintf("%s at %s:%d", SlugToNormalText(r.CheckID), r.Path, r.Start.Line),
			Description: r.Extra.Message,
			Category:    r.GetCategory(),
			Severity:    r.GetSeverity(),
			Confidence:  r.GetConfidence(),
			File:        r.Path,
			StartLine:   r.Start.Line,
			EndLine:     r.End.Line,
			StartColumn: r.Start.Col,
			EndColumn:   r.End.Col,
			Snippet:     r.Extra.Lines,
			CWEs:        r.GetCWEs(),
			References:  r.GetReferences(),
			Fix:         r.Extra.Fix,
		}

		// Parse data flow trace
		if r.Extra.DataflowTrace != nil {
			finding.DataFlow = parseDataFlow(r.Extra.DataflowTrace)
		}

		result.Findings = append(result.Findings, finding)
	}

	return result, nil
}

// parseDataFlow converts semgrep dataflow trace to DataFlowSteps.
func parseDataFlow(df *DataFlow) []DataFlowStep {
	var steps []DataFlowStep

	// Parse taint source
	if source := ConvertCliLoc(df.TaintSource); source != nil {
		steps = append(steps, DataFlowStep{
			File:     source.Location.Path,
			Line:     source.Location.Start.Line,
			Column:   source.Location.Start.Col,
			Content:  source.Content,
			StepType: "source",
		})
	}

	// Parse intermediate vars
	for _, node := range df.IntermediateVars {
		steps = append(steps, DataFlowStep{
			File:     node.Location.Path,
			Line:     node.Location.Start.Line,
			Column:   node.Location.Start.Col,
			Content:  node.Content,
			StepType: "intermediate",
		})
	}

	// Parse taint sink
	sinks := ConvertCliCall(df.TaintSink)
	if len(sinks) == 0 {
		if sink := ConvertCliLoc(df.TaintSink); sink != nil {
			sinks = append(sinks, sink)
		}
	}
	for _, sink := range sinks {
		steps = append(steps, DataFlowStep{
			File:     sink.Location.Path,
			Line:     sink.Location.Start.Line,
			Column:   sink.Location.Start.Col,
			Content:  sink.Content,
			StepType: "sink",
		})
	}

	return steps
}
