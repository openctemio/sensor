package betterleaks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/internal/report"
	"github.com/openctemio/sensor/internal/toolrun"
)

const (
	// DefaultBinary is the default betterleaks binary name.
	DefaultBinary = "betterleaks"

	// DefaultOutputFile is the default output file name.
	DefaultOutputFile = "betterleaks-report.json"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute
)

// Scanner implements the SecretScanner interface for Betterleaks
// (https://github.com/betterleaks/betterleaks), the successor to gitleaks by
// its original author. It needs a v1.x binary: v1 keeps the gitleaks CLI
// flags and JSON report (an array of findings with RuleID, File, StartLine,
// Secret, Match, Fingerprint...). v2 changes the report into an envelope and
// is refused with a clear error by ParseJSONBytes.
type Scanner struct {
	// Configuration
	Binary     string        // Path to betterleaks binary (default: "betterleaks")
	ConfigFile string        // Custom config (.betterleaks.toml; gitleaks .gitleaks.toml files also load)
	OutputFile string        // Report file: an absolute path is used as is; otherwise the base name, in a temporary directory removed after the scan
	Timeout    time.Duration // Scan timeout (default: 30 minutes)
	Verbose    bool          // Enable verbose output

	// Internal
	version string
}

// NewScanner creates a new betterleaks scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:     DefaultBinary,
		OutputFile: DefaultOutputFile,
		Timeout:    DefaultTimeout,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return core.ScannerBetterleaks
}

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType {
	return core.ScannerTypeSecretDetection
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	return []string{
		"secret_detection",
		"api_key_detection",
		"password_detection",
		"private_key_detection",
		"git_history_scan",
	}
}

// IsInstalled checks if betterleaks is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	installed, version, err := core.CheckBinaryInstalled(ctx, s.binary(), "version")
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

// GenericScan implements core.Scanner interface for use with the sensor.
// Returns raw JSON output that can be parsed by the betterleaks parser.
//
// The scan runs out of process, in the task sandbox (tool.go), unless
// SENSOR_TOOL_RUNTIME=in-process.
func (s *Scanner) GenericScan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if toolrun.OutOfProcess() {
		return s.outOfProcess(ctx, target, opts)
	}
	return s.genericScanDirect(ctx, target, opts)
}

// genericScanDirect is the direct path: betterleaks runs as this
// process's child.
func (s *Scanner) genericScanDirect(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()

	// Convert generic options to secret options
	var secretOpts *core.SecretScanOptions
	if opts != nil {
		// CustomTemplateDir holds the platform's custom rules: use its first
		// .toml file as the config.
		configFile := opts.ConfigFile
		if opts.CustomTemplateDir != "" {
			entries, err := os.ReadDir(opts.CustomTemplateDir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() && filepath.Ext(entry.Name()) == ".toml" {
						configFile = filepath.Join(opts.CustomTemplateDir, entry.Name())
						break
					}
				}
			}
		}
		secretOpts = &core.SecretScanOptions{
			TargetDir:  opts.TargetDir,
			ConfigFile: configFile,
			Exclude:    opts.Exclude,
			Verbose:    opts.Verbose,
		}
	}

	absTarget, outputData, exitCode, stderr, err := s.run(ctx, target, secretOpts)
	if err != nil {
		return nil, err
	}

	// Exclusions are applied to the report: betterleaks (like gitleaks
	// before it) has no --exclude-path flag.
	if secretOpts != nil && len(secretOpts.Exclude) > 0 {
		findings, err := ParseJSONBytes(outputData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse betterleaks output: %w", err)
		}
		outputData, err = json.Marshal(filterExcluded(findings, absTarget, secretOpts.Exclude))
		if err != nil {
			return nil, fmt.Errorf("failed to re-encode betterleaks output: %w", err)
		}
	}

	result := &core.ScanResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		ExitCode:       exitCode,
		RawOutput:      outputData,
		Stderr:         stderr,
	}

	if s.Verbose {
		fmt.Printf("[betterleaks] Scan completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// Scan performs a betterleaks scan on the target directory and returns structured SecretResult.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.SecretScanOptions) (*core.SecretResult, error) {
	start := time.Now()

	absTarget, outputData, _, _, err := s.run(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	findings, err := ParseJSONBytes(outputData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse betterleaks output: %w", err)
	}
	if opts != nil {
		findings = filterExcluded(findings, absTarget, opts.Exclude)
	}

	result := s.convertFindings(findings)
	result.DurationMs = time.Since(start).Milliseconds()

	if s.Verbose {
		fmt.Printf("[betterleaks] Found %d secrets in %dms\n", len(result.Secrets), result.DurationMs)
	}

	return result, nil
}

// run executes betterleaks over target and returns the absolute target, the
// raw JSON report, the exit code and stderr.
func (s *Scanner) run(ctx context.Context, target string, opts *core.SecretScanOptions) (string, []byte, int, string, error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", nil, 0, "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	// The report never goes into the scanned tree (it may be read-only):
	// a relative OutputFile lands in a private temporary directory.
	outputFile, cleanupReport, err := report.Path(s.OutputFile, DefaultOutputFile, core.ScannerBetterleaks)
	if err != nil {
		return "", nil, 0, "", err
	}
	defer cleanupReport()

	args := s.buildArgs(absTarget, outputFile, opts)

	if s.Verbose {
		fmt.Printf("[betterleaks] Scanning %s\n", absTarget)
		fmt.Printf("[betterleaks] Output: %s\n", outputFile)
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  s.binary(),
		Args:    args,
		WorkDir: absTarget,
		Timeout: timeout,
		Verbose: s.Verbose,
		// The tool sandbox lets it write only its report's directory.
		WritePaths: []string{filepath.Dir(outputFile)},
	})
	if err != nil {
		return "", nil, 0, "", fmt.Errorf("failed to execute betterleaks: %w", err)
	}

	// Exit codes: 0 = no leaks (or leaks with --exit-code 0), 1 = leaks
	// found, anything else is an error.
	if execResult.ExitCode != 0 && execResult.ExitCode != 1 {
		return "", nil, 0, "", fmt.Errorf("betterleaks exited with code %d: %s", execResult.ExitCode, string(execResult.Stderr))
	}

	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return "", nil, 0, "", fmt.Errorf("failed to read betterleaks output: %w", err)
	}
	_ = os.Remove(outputFile)

	return absTarget, outputData, execResult.ExitCode, string(execResult.Stderr), nil
}

func (s *Scanner) binary() string {
	if s.Binary == "" {
		return DefaultBinary
	}
	return s.Binary
}

// buildArgs builds the betterleaks command arguments.
//
// Only flags betterleaks v1 accepts are passed. The old gitleaks scanner also
// passed --exclude-path and --no-git, which neither tool's `dir` command
// knows, so any scan with exclusions failed outright; exclusions are now
// applied to the report (filterExcluded).
func (s *Scanner) buildArgs(target, outputFile string, opts *core.SecretScanOptions) []string {
	args := []string{
		"dir",  // Scan directory mode
		target, // Target directory
		"--report-format", "json",
		"--report-path", outputFile,
		"--exit-code", "0", // Don't fail on findings
		"--no-banner",
	}

	// Add config file if specified
	configFile := s.ConfigFile
	if opts != nil && opts.ConfigFile != "" {
		configFile = opts.ConfigFile
	}
	if configFile != "" {
		args = append(args, "--config", configFile)
	}

	// Report findings marked with inline betterleaks:allow / gitleaks:allow
	// comments too: suppression is decided by the platform, not the repo.
	args = append(args, "--ignore-gitleaks-allow")

	// Never --verbose: it prints every finding with its raw secret to stdout,
	// which a verbose sensor copies into its log. (--redact is no fix: it
	// also rewrites the report's Secret, which changes masked values and
	// fingerprints.) The scanner's own Verbose output stays.

	return args
}

// filterExcluded drops findings whose path (relative to root) matches one of
// the exclude patterns. A pattern matches a path glob (path.Match), a base
// name, or a directory prefix ("vendor" and "vendor/" exclude vendor/**).
func filterExcluded(findings []Finding, root string, exclude []string) []Finding {
	if len(exclude) == 0 {
		return findings
	}
	kept := findings[:0:0]
	for _, f := range findings {
		if !excluded(relTo(root, f.File), exclude) {
			kept = append(kept, f)
		}
	}
	return kept
}

func relTo(root, file string) string {
	if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(file)
}

func excluded(rel string, patterns []string) bool {
	// An archive member is reported as "dir/bundle.zip!member": match on
	// the archive's own path.
	if i := strings.IndexByte(rel, '!'); i >= 0 {
		rel = rel[:i]
	}
	for _, p := range patterns {
		p = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(p)), "./")
		if p == "" {
			continue
		}
		dir := strings.TrimSuffix(p, "/")
		if rel == dir || strings.HasPrefix(rel, dir+"/") {
			return true
		}
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		if ok, _ := path.Match(p, path.Base(rel)); ok {
			return true
		}
	}
	return false
}

// convertFindings converts betterleaks findings to SecretResult.
func (s *Scanner) convertFindings(findings []Finding) *core.SecretResult {
	result := &core.SecretResult{
		Secrets: make([]core.SecretFinding, 0, len(findings)),
	}

	for _, f := range findings {
		secret := core.SecretFinding{
			RuleID:      f.RuleID,
			Fingerprint: s.generateFingerprint(f),
			SecretType:  GetSecretType(f.RuleID),
			Service:     GetServiceName(f.RuleID),

			// Location
			File:        f.File,
			StartLine:   f.StartLine,
			EndLine:     f.EndLine,
			StartColumn: f.StartColumn,
			EndColumn:   f.EndColumn,

			// Content
			// SECURITY: never expose the raw secret in Match.
			Match:       core.MaskSecretInText(f.Match, f.Secret),
			MaskedValue: core.MaskSecret(f.Secret),

			// Metadata
			Entropy: f.Entropy,
			Author:  f.Author,
			Commit:  f.Commit,
			Date:    f.Date,
		}

		result.Secrets = append(result.Secrets, secret)
	}

	return result
}

// generateFingerprint generates a unique fingerprint for a finding.
func (s *Scanner) generateFingerprint(f Finding) string {
	// Use the tool's fingerprint if available
	if f.Fingerprint != "" {
		return f.Fingerprint
	}

	// Generate our own fingerprint
	// SECURITY (CTIS spec 5.2): never hash the raw secret. An unsalted
	// hash of a short secret is reversible by brute force; the masked
	// value carries nothing the masked_value field does not already show.
	return core.GenerateSecretFingerprint(f.File, f.RuleID, f.StartLine, core.MaskSecret(f.Secret))
}
