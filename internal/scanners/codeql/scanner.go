package codeql

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/internal/report"
	"github.com/openctemio/sensor/internal/toolrun"
)

const (
	// DefaultBinary is the default CodeQL CLI binary name.
	DefaultBinary = "codeql"

	// DefaultOutputFile is the default SARIF output file name.
	DefaultOutputFile = "codeql-results.sarif"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 60 * time.Minute

	// DefaultQuerySuite is the default security query suite.
	DefaultQuerySuite = "security-extended"
)

// Scanner implements the SAST scanner interface for CodeQL.
// CodeQL provides full inter-procedural dataflow analysis, making it ideal
// for detecting vulnerabilities that require taint tracking across functions
// and files.
type Scanner struct {
	// Configuration
	Binary     string        // Path to codeql binary (default: "codeql")
	OutputFile string        // Report file: an absolute path is used as is; otherwise the base name, in a temporary directory removed after the scan
	Timeout    time.Duration // Scan timeout (default: 60 minutes)
	Verbose    bool          // Enable verbose output

	// CodeQL-specific options
	Language       Language // Target language (required)
	DatabasePath   string   // Path to CodeQL database (optional: when empty, built in a temporary directory removed after the scan)
	QueryPacks     []string // Query packs to use (default: security-extended)
	QueryFiles     []string // Specific .ql files to run
	Threads        int      // Number of threads (0 = auto)
	RAMPerThread   int      // RAM per thread in MB (0 = default)
	Format         string   // Output format (sarif-latest, csv, json)
	SkipDBCreation bool     // Skip database creation (use existing)

	// Internal
	version string
}

// NewScanner creates a new CodeQL scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:     DefaultBinary,
		OutputFile: DefaultOutputFile,
		Timeout:    DefaultTimeout,
		QueryPacks: []string{DefaultQuerySuite},
		Format:     "sarif-latest",
	}
}

// NewSecurityScanner creates a scanner focused on security vulnerabilities.
func NewSecurityScanner(lang Language) *Scanner {
	s := NewScanner()
	s.Language = lang
	s.QueryPacks = []string{"security-extended"}
	return s
}

// NewQualityScanner creates a scanner for code quality issues.
func NewQualityScanner(lang Language) *Scanner {
	s := NewScanner()
	s.Language = lang
	s.QueryPacks = []string{"security-and-quality"}
	return s
}

// NewFullScanner creates a scanner that runs all available queries.
func NewFullScanner(lang Language) *Scanner {
	s := NewScanner()
	s.Language = lang
	s.QueryPacks = []string{"security-and-quality"}
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "codeql"
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
	return []string{
		"sast",
		"code_analysis",
		"vulnerability_detection",
		"taint_tracking",
		"cross_file_analysis",
		"interprocedural_analysis",
		"dataflow_analysis",
		"security_queries",
		"code_quality",
	}
}

// IsInstalled checks if CodeQL is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	installed, version, err := core.CheckBinaryInstalled(ctx, binary, "version")
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

// Scan performs a CodeQL scan on the target.
//
// The scan runs out of process, in the task sandbox (tool.go), unless
// SENSOR_TOOL_RUNTIME=in-process.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if toolrun.OutOfProcess() {
		return s.outOfProcess(ctx, target, opts)
	}
	return s.scanDirect(ctx, target, opts)
}

// scanDirect is the direct path: codeql runs as this process's child.
func (s *Scanner) scanDirect(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()

	// Validate language
	if s.Language == "" {
		return nil, fmt.Errorf("language is required for CodeQL scanning")
	}
	if !s.Language.IsValid() {
		return nil, fmt.Errorf("unsupported language: %s", s.Language)
	}

	// Resolve target path
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}

	// Determine database path
	dbPath := s.DatabasePath
	if dbPath == "" {
		if s.SkipDBCreation {
			// Analyze the database a previous run left in the tree.
			dbPath = filepath.Join(absTarget, ".codeql-db")
		} else {
			// A database built for this run goes outside the scanned
			// tree (it may be read-only) and is removed afterwards.
			dbDir, err := os.MkdirTemp("", "openctem-codeql-db-*")
			if err != nil {
				return nil, fmt.Errorf("create codeql database directory: %w", err)
			}
			defer func() { _ = os.RemoveAll(dbDir) }()
			dbPath = filepath.Join(dbDir, "db")
		}
	}

	// The report never goes into the scanned tree (it may be read-only):
	// a relative OutputFile lands in a private temporary directory.
	outputFile, cleanupReport, err := report.Path(s.OutputFile, DefaultOutputFile, "codeql")
	if err != nil {
		return nil, err
	}
	defer cleanupReport()

	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Step 1: Create CodeQL database (if needed)
	if !s.SkipDBCreation {
		if err := s.createDatabase(ctx, binary, absTarget, dbPath, timeout); err != nil {
			return nil, fmt.Errorf("failed to create CodeQL database: %w", err)
		}
	}

	// Step 2: Run analysis
	args := s.buildAnalyzeArgs(dbPath, outputFile)

	if s.Verbose {
		fmt.Printf("[codeql] Analyzing database: %s\n", dbPath)
		fmt.Printf("[codeql] Output: %s\n", outputFile)
		fmt.Printf("[codeql] Command: %s %s\n", binary, strings.Join(args, " "))
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		WorkDir: absTarget,
		Timeout: timeout,
		Verbose: s.Verbose,
		// The tool sandbox: the database (results cache) and the report.
		WritePaths: []string{dbPath, filepath.Dir(outputFile)},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute CodeQL analysis: %w", err)
	}

	// CodeQL exit codes:
	// 0 = success
	// 1 = error
	// 2 = results found (still success)
	if execResult.ExitCode == 1 {
		return nil, fmt.Errorf("codeql analysis failed: %s", string(execResult.Stderr))
	}

	// Read output file
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CodeQL output: %w", err)
	}

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
		fmt.Printf("[codeql] Analysis completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// createDatabase creates a CodeQL database for the target.
func (s *Scanner) createDatabase(ctx context.Context, binary, sourceRoot, dbPath string, timeout time.Duration) error {
	if s.Verbose {
		fmt.Printf("[codeql] Creating database for %s (%s)\n", sourceRoot, s.Language)
	}

	// Remove existing database. os.RemoveAll is idempotent (returns nil
	// when the path is absent) and atomic at the syscall level, so
	// calling it directly closes the TOCTOU window an earlier `Stat ->
	// RemoveAll` pattern opened: an attacker could have symlinked
	// dbPath between the Stat and the Remove and had the Remove walk
	// into a directory outside the scanner workspace. Relying on
	// RemoveAll's built-in "not exist = ok" semantics avoids that gap.
	if err := os.RemoveAll(dbPath); err != nil {
		return fmt.Errorf("failed to remove existing database: %w", err)
	}

	args := []string{
		"database", "create",
		dbPath,
		"--language=" + s.Language.String(),
		"--source-root=" + sourceRoot,
		"--overwrite",
	}

	if s.Threads > 0 {
		args = append(args, fmt.Sprintf("--threads=%d", s.Threads))
	}

	if s.RAMPerThread > 0 {
		args = append(args, fmt.Sprintf("--ram=%d", s.RAMPerThread*s.Threads))
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		WorkDir: sourceRoot,
		Timeout: timeout,
		Verbose: s.Verbose,
		// The tool sandbox: the database it creates (its parent, as the
		// directory is replaced).
		WritePaths: []string{filepath.Dir(dbPath)},
	})

	if err != nil {
		return err
	}

	if execResult.ExitCode != 0 {
		return fmt.Errorf("database creation failed (exit %d): %s", execResult.ExitCode, string(execResult.Stderr))
	}

	if s.Verbose {
		fmt.Printf("[codeql] Database created at %s\n", dbPath)
	}

	return nil
}

// buildAnalyzeArgs builds the codeql database analyze command arguments.
func (s *Scanner) buildAnalyzeArgs(dbPath, outputFile string) []string {
	args := []string{
		"database", "analyze",
		dbPath,
		"--format=" + s.Format,
		"--output=" + outputFile,
		"--sarif-add-query-help",
	}

	// Query packs
	for _, pack := range s.QueryPacks {
		// Use codeql/<language>-queries:<pack>
		queryPath := fmt.Sprintf("codeql/%s-queries:%s", s.Language, pack)
		args = append(args, queryPath)
	}

	// Specific query files
	args = append(args, s.QueryFiles...)

	// Threads
	if s.Threads > 0 {
		args = append(args, fmt.Sprintf("--threads=%d", s.Threads))
	}

	// RAM
	if s.RAMPerThread > 0 {
		args = append(args, fmt.Sprintf("--ram=%d", s.RAMPerThread*s.Threads))
	}

	return args
}

// AnalyzeExistingDatabase analyzes a pre-built CodeQL database.
func (s *Scanner) AnalyzeExistingDatabase(ctx context.Context, dbPath string, opts *core.ScanOptions) (*core.ScanResult, error) {
	s.SkipDBCreation = true
	s.DatabasePath = dbPath
	return s.Scan(ctx, filepath.Dir(dbPath), opts)
}
