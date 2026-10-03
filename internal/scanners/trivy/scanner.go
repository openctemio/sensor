package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBinary is the default trivy binary name.
	DefaultBinary = "trivy"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute
)

// Scanner implements the ScaScanner interface for Trivy.
type Scanner struct {
	// Configuration
	Binary   string        // Path to trivy binary (default: "trivy")
	Timeout  time.Duration // Scan timeout (default: 30 minutes)
	Verbose  bool          // Enable verbose output
	CacheDir string        // Trivy cache directory

	// Scan options
	Mode          ScanMode // fs, config, image, repo
	Scanners      []string // vuln, misconfig, secret, license
	Severity      []string // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	IgnoreUnfixed bool     // Ignore unfixed vulnerabilities
	SkipDBUpdate  bool     // Skip vulnerability DB update
	OfflineScan   bool     // Run in offline mode
	TrivyExitCode int      // Exit code when vulnerabilities found (default: 0)

	// Output options
	OutputFile string // Output file path (empty = stdout)

	// Exclude paths
	SkipDirs  []string // Directories to skip
	SkipFiles []string // Files to skip

	// Image scanning options
	IgnorePolicy string // OPA policy file for ignoring

	// Internal
	version string
}

// NewScanner creates a new Trivy scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:        DefaultBinary,
		Timeout:       DefaultTimeout,
		Mode:          ScanModeFS,
		Scanners:      []string{"vuln"},
		Severity:      []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
		TrivyExitCode: 0,
	}
}

// NewConfigScanner creates a scanner configured for IaC scanning.
func NewConfigScanner() *Scanner {
	s := NewScanner()
	s.Mode = ScanModeConfig
	s.Scanners = []string{"misconfig"}
	return s
}

// NewImageScanner creates a scanner configured for container image scanning.
func NewImageScanner() *Scanner {
	s := NewScanner()
	s.Mode = ScanModeImage
	s.Scanners = []string{"vuln"}
	return s
}

// NewFullScanner creates a scanner that scans for all types.
func NewFullScanner() *Scanner {
	s := NewScanner()
	s.Scanners = []string{"vuln", "misconfig", "secret"}
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "trivy"
}

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType {
	switch s.Mode {
	case ScanModeConfig:
		return core.ScannerTypeIaC
	case ScanModeImage:
		return core.ScannerTypeContainer
	default:
		return core.ScannerTypeDependency
	}
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	caps := []string{}
	for _, scanner := range s.Scanners {
		switch scanner {
		case "vuln":
			caps = append(caps, "vulnerability", "sca")
		case "misconfig":
			caps = append(caps, "misconfiguration", "iac")
		case "secret":
			caps = append(caps, "secret_detection")
		case "license":
			caps = append(caps, "license_compliance")
		}
	}
	return caps
}

// IsInstalled checks if Trivy is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	installed, version, err := core.CheckBinaryInstalled(ctx, binary, "version", "--format", "json")
	if err != nil {
		// Try without --format json for older versions
		installed, version, err = core.CheckBinaryInstalled(ctx, binary, "version")
		if err != nil {
			return false, "", err
		}
	}

	if installed {
		// Parse version from output
		s.version = parseVersion(version)
	}

	return installed, s.version, nil
}

// parseVersion extracts version from trivy output.
func parseVersion(output string) string {
	// Try JSON format first
	var versionInfo struct {
		Version string `json:"Version"`
	}
	if json.Unmarshal([]byte(output), &versionInfo) == nil && versionInfo.Version != "" {
		return versionInfo.Version
	}

	// Parse text format: "Version: 0.48.0"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}

	return strings.TrimSpace(output)
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// Scan implements core.Scanner interface - returns raw JSON output.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()

	// Resolve target path for fs/config modes
	absTarget := target
	if s.Mode == ScanModeFS || s.Mode == ScanModeConfig || s.Mode == ScanModeRepo {
		var err error
		absTarget, err = filepath.Abs(target)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve target path: %w", err)
		}
	}

	// Build trivy arguments
	args := s.buildArgs(absTarget, opts)

	if s.Verbose {
		fmt.Printf("[trivy] Mode: %s\n", s.Mode)
		fmt.Printf("[trivy] Target: %s\n", absTarget)
		fmt.Printf("[trivy] Scanners: %v\n", s.Scanners)
	}

	// Execute trivy
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	workDir := ""
	if s.Mode == ScanModeFS || s.Mode == ScanModeConfig {
		workDir = absTarget
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		WorkDir: workDir,
		Timeout: timeout,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute trivy: %w", err)
	}

	// Trivy exit codes:
	// 0 = success, no vulnerabilities found (or exitCode set to 0)
	// 1 = vulnerabilities found (when exit-code is set)
	// other = error
	if execResult.ExitCode != 0 && execResult.ExitCode != s.TrivyExitCode && execResult.ExitCode != 1 {
		return nil, fmt.Errorf("trivy exited with code %d: %s", execResult.ExitCode, string(execResult.Stderr))
	}

	// Get output (from file or stdout)
	var outputData []byte
	if s.OutputFile != "" {
		outputData, err = os.ReadFile(s.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read trivy output: %w", err)
		}
		// Clean up output file
		_ = os.Remove(s.OutputFile)
	} else {
		outputData = execResult.Stdout
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
		fmt.Printf("[trivy] Scan completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// ScanSCA implements core.ScaScanner interface - returns structured ScaResult.
func (s *Scanner) ScanSCA(ctx context.Context, target string, opts *core.ScaScanOptions) (*core.ScaResult, error) {
	start := time.Now()

	// Ensure vuln scanner is enabled
	if !contains(s.Scanners, "vuln") {
		s.Scanners = append(s.Scanners, "vuln")
	}

	// Apply ScaScanOptions
	if opts != nil {
		if opts.SkipDBUpdate {
			s.SkipDBUpdate = true
		}
		if opts.IgnoreUnfixed {
			s.IgnoreUnfixed = true
		}
	}

	// Convert options
	var scanOpts *core.ScanOptions
	if opts != nil {
		scanOpts = &core.ScanOptions{
			TargetDir: opts.TargetDir,
			Verbose:   opts.Verbose,
		}
	}

	// Run scan
	scanResult, err := s.Scan(ctx, target, scanOpts)
	if err != nil {
		return nil, err
	}

	// Parse output
	var report Report
	if err := json.Unmarshal(scanResult.RawOutput, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Convert to ScaResult
	result := s.convertToScaResult(&report, target)
	result.DurationMs = time.Since(start).Milliseconds()

	if s.Verbose {
		fmt.Printf("[trivy] Found %d vulnerabilities in %dms\n", len(result.Vulnerabilities), result.DurationMs)
	}

	return result, nil
}

// buildArgs builds the trivy command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ScanOptions) []string {
	args := []string{
		string(s.Mode),
	}

	// Output format
	args = append(args, "--format", "json")

	// Output file
	if s.OutputFile != "" {
		args = append(args, "--output", s.OutputFile)
	}

	// Scanners
	if len(s.Scanners) > 0 {
		args = append(args, "--scanners", strings.Join(s.Scanners, ","))
	}

	// Severity filter
	if len(s.Severity) > 0 {
		args = append(args, "--severity", strings.Join(s.Severity, ","))
	}

	// Ignore unfixed
	if s.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	// Skip DB update
	if s.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	// Offline mode
	if s.OfflineScan {
		args = append(args, "--offline-scan")
	}

	// Exit code
	args = append(args, "--exit-code", fmt.Sprintf("%d", s.TrivyExitCode))

	// Cache directory
	if s.CacheDir != "" {
		args = append(args, "--cache-dir", s.CacheDir)
	}

	// Ignore policy
	if s.IgnorePolicy != "" {
		args = append(args, "--ignore-policy", s.IgnorePolicy)
	}

	// Skip directories
	for _, dir := range s.SkipDirs {
		args = append(args, "--skip-dirs", dir)
	}

	// Skip files
	for _, file := range s.SkipFiles {
		args = append(args, "--skip-files", file)
	}

	// Exclude paths from options
	if opts != nil {
		for _, exclude := range opts.Exclude {
			args = append(args, "--skip-dirs", exclude)
		}
	}

	// Target
	args = append(args, target)

	return args
}

// convertToScaResult converts Trivy report to core.ScaResult.
func (s *Scanner) convertToScaResult(report *Report, target string) *core.ScaResult {
	result := &core.ScaResult{
		Packages:            []core.Package{},
		PackageDependencies: []core.PackageDependency{},
		Vulnerabilities:     []core.Vulnerability{},
	}

	// Track unique packages
	pkgMap := make(map[string]*core.Package)

	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			// Get CVSS info
			cvssScore, cvssVector, cvssSource := GetBestCVSSScore(vuln.CVSS)

			// Generate fingerprint
			fingerprint := generateFingerprint(vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, target)

			finding := core.Vulnerability{
				ID:           vuln.VulnerabilityID,
				Fingerprint:  fingerprint,
				PkgID:        fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion),
				PkgName:      vuln.PkgName,
				PkgVersion:   vuln.InstalledVersion,
				Name:         vuln.Title,
				Description:  vuln.Description,
				Severity:     GetCTISSeverity(vuln.Severity),
				FixedVersion: vuln.FixedVersion,
				Metadata: &core.VulnerabilityMetadata{
					CWEs:       vuln.CweIDs,
					References: vuln.References,
					CVSSScore:  cvssScore,
					CVSSVector: cvssVector,
					Source:     cvssSource,
				},
			}

			result.Vulnerabilities = append(result.Vulnerabilities, finding)

			// Track package
			pkgID := fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion)
			if _, exists := pkgMap[pkgID]; !exists {
				purl := buildPURL(res.Type, vuln.PkgName, vuln.InstalledVersion)
				pkgMap[pkgID] = &core.Package{
					ID:       pkgID,
					Name:     vuln.PkgName,
					Version:  vuln.InstalledVersion,
					Type:     res.Type,
					PURL:     purl,
					Licenses: []string{},
				}
			}
		}

		// Also add packages from licenses if available
		for _, lic := range res.Licenses {
			pkgID := fmt.Sprintf("%s@unknown", lic.PkgName)
			if _, exists := pkgMap[pkgID]; !exists {
				pkgMap[pkgID] = &core.Package{
					ID:       pkgID,
					Name:     lic.PkgName,
					Version:  "unknown",
					Type:     res.Type,
					Licenses: []string{lic.Name},
				}
			} else {
				// Append license to existing package
				pkgMap[pkgID].Licenses = append(pkgMap[pkgID].Licenses, lic.Name)
			}
		}
	}

	// Convert package map to slice
	for _, pkg := range pkgMap {
		result.Packages = append(result.Packages, *pkg)
	}

	return result
}

// generateFingerprint generates a unique fingerprint for a vulnerability.
func generateFingerprint(vulnID, pkgName, pkgVersion, target string) string {
	data := fmt.Sprintf("%s:%s:%s:%s", vulnID, pkgName, pkgVersion, target)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16])
}

// buildPURL builds a Package URL from components.
func buildPURL(ecosystem, name, version string) string {
	// Map Trivy ecosystem to PURL type
	purlType := strings.ToLower(ecosystem)
	switch ecosystem {
	case "alpine", "debian", "ubuntu", "redhat", "centos", "amazon":
		purlType = "deb"
	case "npm", "yarn":
		purlType = "npm"
	case "pip", "pipenv", "poetry":
		purlType = "pypi"
	case "gem", "bundler":
		purlType = "gem"
	case "go", "gomod":
		purlType = "golang"
	case "cargo":
		purlType = "cargo"
	case "nuget":
		purlType = "nuget"
	case "maven", "gradle":
		purlType = "maven"
	case "composer":
		purlType = "composer"
	case "cocoapods":
		purlType = "cocoapods"
	case "swift":
		purlType = "swift"
	case "pub":
		purlType = "pub"
	case "hex":
		purlType = "hex"
	}

	return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
}

// contains checks if a string slice contains a value.
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
