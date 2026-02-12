package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
	"github.com/openctemio/sdk-go/pkg/scanners/nuclei"
	"github.com/openctemio/sdk-go/pkg/scanners/semgrep"
	"github.com/openctemio/sdk-go/pkg/scanners/trivy"
)

// =============================================================================
// VULNSCAN EXECUTOR
// =============================================================================

// VulnScanExecutor handles vulnerability scanning jobs using various tools.
// Supports: nuclei (DAST), trivy (SCA/container), semgrep (SAST)
type VulnScanExecutor struct {
	mu sync.RWMutex

	// Available tools
	tools map[string]ToolExecutor

	// Configuration
	config *VulnScanConfig

	// State
	enabled bool

	// Result pusher
	pusher ResultPusher
}

// VulnScanConfig configures the vulnerability scan executor.
type VulnScanConfig struct {
	Enabled bool

	// Tool-specific configs
	Nuclei  NucleiConfig
	Trivy   TrivyConfig
	Semgrep SemgrepConfig

	// Common settings
	Verbose bool
}

// NucleiConfig configures nuclei scanner.
type NucleiConfig struct {
	Enabled       bool
	TemplatesPath string
	RateLimit     int
	Concurrency   int
	Severity      []string // critical, high, medium, low, info
}

// TrivyConfig configures trivy scanner.
type TrivyConfig struct {
	Enabled    bool
	CacheDir   string
	Severity   []string
	IgnoreFile string
	ScanTypes  []string // vuln, config, secret, license
}

// SemgrepConfig configures semgrep scanner.
type SemgrepConfig struct {
	Enabled        bool
	Config         string // rules config (auto, p/default, path to rules)
	Exclude        []string
	DataflowTraces bool // Enable --dataflow-traces for taint tracking paths
}

// NewVulnScanExecutor creates a new vulnerability scan executor.
func NewVulnScanExecutor(cfg *VulnScanConfig, pusher ResultPusher) *VulnScanExecutor {
	e := &VulnScanExecutor{
		tools:   make(map[string]ToolExecutor),
		config:  cfg,
		enabled: cfg.Enabled,
		pusher:  pusher,
	}

	// Register tools
	if cfg.Nuclei.Enabled {
		e.tools["nuclei"] = &NucleiTool{config: &cfg.Nuclei, verbose: cfg.Verbose}
	}
	if cfg.Trivy.Enabled {
		e.tools["trivy"] = &TrivyTool{config: &cfg.Trivy, verbose: cfg.Verbose}
	}
	if cfg.Semgrep.Enabled {
		e.tools["semgrep"] = &SemgrepTool{config: &cfg.Semgrep, verbose: cfg.Verbose}
	}

	return e
}

// Name returns the executor name.
func (e *VulnScanExecutor) Name() string {
	return "vulnscan"
}

// IsEnabled returns whether the executor is enabled.
func (e *VulnScanExecutor) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// Capabilities returns supported scan types.
func (e *VulnScanExecutor) Capabilities() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	caps := []string{}
	for _, tool := range e.tools {
		caps = append(caps, tool.Capabilities()...)
	}
	return caps
}

// InstalledTools returns list of installed scanning tools.
func (e *VulnScanExecutor) InstalledTools() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var tools []string
	for name, tool := range e.tools {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		installed, _, _ := tool.IsInstalled(ctx)
		cancel()
		if installed {
			tools = append(tools, name)
		}
	}
	return tools
}

// Execute runs a vulnerability scan job.
func (e *VulnScanExecutor) Execute(ctx context.Context, job *platform.JobInfo) (*platform.JobResult, error) {
	startTime := time.Now()

	// Extract scanner from payload
	scannerName, _ := job.Payload["scanner"].(string)
	if scannerName == "" {
		scannerName, _ = job.Payload["scanner_name"].(string)
	}
	if scannerName == "" {
		// Infer from job type
		switch job.Type {
		case "sast":
			scannerName = "semgrep"
		case "sca", "container":
			scannerName = "trivy"
		case "dast", "scan", "vulnscan":
			scannerName = "nuclei"
		default:
			scannerName = "nuclei"
		}
	}

	// Get tool
	e.mu.RLock()
	tool, ok := e.tools[scannerName]
	e.mu.RUnlock()

	if !ok {
		return &platform.JobResult{
			JobID:      job.ID,
			Status:     "failed",
			Error:      fmt.Sprintf("scanner %s not configured", scannerName),
			DurationMs: time.Since(startTime).Milliseconds(),
		}, fmt.Errorf("%w: %s", ErrToolNotInstalled, scannerName)
	}

	// Check if installed
	installed, _, err := tool.IsInstalled(ctx)
	if err != nil || !installed {
		return &platform.JobResult{
			JobID:      job.ID,
			Status:     "failed",
			Error:      fmt.Sprintf("scanner %s not installed", scannerName),
			DurationMs: time.Since(startTime).Milliseconds(),
		}, fmt.Errorf("%w: %s", ErrToolNotInstalled, scannerName)
	}

	// Build tool options from job payload
	opts := e.buildToolOptions(job)

	// Execute tool
	result, err := tool.Execute(ctx, opts)
	if err != nil {
		return &platform.JobResult{
			JobID:      job.ID,
			Status:     "failed",
			Error:      fmt.Sprintf("scan failed: %v", err),
			DurationMs: time.Since(startTime).Milliseconds(),
		}, err
	}

	// Parse findings
	// Pass target path for snippet extraction (needed for Semgrep OSS which returns "requires login")
	// Convert to absolute path for reliable file reading
	targetAbsPath := opts.Target
	if !filepath.IsAbs(opts.Target) {
		if absPath, err := filepath.Abs(opts.Target); err == nil {
			targetAbsPath = absPath
		}
	}
	findings, err := e.parseFindings(scannerName, result, targetAbsPath)
	if err != nil {
		return &platform.JobResult{
			JobID:      job.ID,
			Status:     "failed",
			Error:      fmt.Sprintf("failed to parse findings: %v", err),
			DurationMs: time.Since(startTime).Milliseconds(),
		}, err
	}

	// Push findings if pusher is configured
	if e.pusher != nil && len(findings) > 0 {
		// Create a full CTIS report with metadata
		report := e.createReport(job, scannerName, findings)

		if err := e.pusher.PushCTIS(ctx, report); err != nil {
			// Log but don't fail the job
			fmt.Printf("[vulnscan] Warning: failed to push findings: %v\n", err)
		}
	}

	return &platform.JobResult{
		JobID:         job.ID,
		Status:        "completed",
		CompletedAt:   time.Now(),
		DurationMs:    time.Since(startTime).Milliseconds(),
		FindingsCount: len(findings),
	}, nil
}

// createReport creates a full CTIS report with metadata from job and findings.
func (e *VulnScanExecutor) createReport(job *platform.JobInfo, scannerName string, findings []ctis.Finding) *ctis.Report {
	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID:         job.ID,
			Timestamp:  time.Now(),
			SourceType: "vulnscan",
			SourceRef:  job.ID,
		},
		Tool: &ctis.Tool{
			Name: scannerName,
		},
		Findings: findings,
	}

	// Extract repo/branch info from payload
	payload := e.parseVulnScanPayload(job)
	if payload != nil {
		e.enrichReportMetadata(report, payload)
	}

	return report
}

// vulnScanPayload contains job payload with repo context.
type vulnScanPayload struct {
	Scanner   string   `json:"scanner"`
	Target    string   `json:"target"`
	Targets   []string `json:"targets"`

	// Repository context for asset creation
	RepoURL   string `json:"repo_url"`
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
	IsDefault bool   `json:"is_default_branch"`
}

// parseVulnScanPayload extracts payload with repo context.
func (e *VulnScanExecutor) parseVulnScanPayload(job *platform.JobInfo) *vulnScanPayload {
	data, err := json.Marshal(job.Payload)
	if err != nil {
		return nil
	}

	var payload vulnScanPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}

	return &payload
}

// enrichReportMetadata adds repo/branch info to the report for asset creation.
func (e *VulnScanExecutor) enrichReportMetadata(report *ctis.Report, payload *vulnScanPayload) {
	// Add branch info if available (for auto-create asset in ingest)
	if payload.RepoURL != "" || payload.Branch != "" {
		report.Metadata.Branch = &ctis.BranchInfo{
			RepositoryURL:   payload.RepoURL,
			Name:            payload.Branch,
			CommitSHA:       payload.CommitSHA,
			IsDefaultBranch: payload.IsDefault,
		}

		if e.config.Verbose {
			fmt.Printf("[vulnscan] Added branch info to report: repo=%s branch=%s\n", payload.RepoURL, payload.Branch)
		}
	}

	// Add explicit asset if repo URL is provided
	if payload.RepoURL != "" {
		asset := ctis.Asset{
			ID:          "asset-1",
			Type:        ctis.AssetTypeRepository,
			Name:        payload.RepoURL,
			Value:       payload.RepoURL,
			Criticality: ctis.CriticalityHigh,
			Properties: ctis.Properties{
				"branch":            payload.Branch,
				"commit_sha":        payload.CommitSHA,
				"is_default_branch": payload.IsDefault,
			},
		}
		report.Assets = append(report.Assets, asset)

		// Link all findings to this asset
		for i := range report.Findings {
			report.Findings[i].AssetRef = "asset-1"
		}

		if e.config.Verbose {
			fmt.Printf("[vulnscan] Added asset to report: %s\n", payload.RepoURL)
		}
	}
}

// buildToolOptions creates ToolOptions from job payload.
func (e *VulnScanExecutor) buildToolOptions(job *platform.JobInfo) ToolOptions {
	opts := ToolOptions{
		OutputFormat: "json",
		Verbose:      e.config.Verbose,
	}

	// Extract target
	if target, ok := job.Payload["target"].(string); ok {
		opts.Target = target
	}
	if targets, ok := job.Payload["targets"].([]interface{}); ok {
		for _, t := range targets {
			if s, ok := t.(string); ok {
				opts.Targets = append(opts.Targets, s)
			}
		}
	}

	// Extract timeout
	if timeout, ok := job.Payload["timeout"].(float64); ok {
		opts.Timeout = int(timeout)
	}

	// Extract rate limit
	if rateLimit, ok := job.Payload["rate_limit"].(float64); ok {
		opts.RateLimit = int(rateLimit)
	}

	// Extract threads
	if threads, ok := job.Payload["threads"].(float64); ok {
		opts.Threads = int(threads)
	}

	return opts
}

// parseFindings converts tool output to CTIS findings.
func (e *VulnScanExecutor) parseFindings(scanner string, result *ToolResult, targetPath string) ([]ctis.Finding, error) {
	switch scanner {
	case "nuclei":
		return parseNucleiFindings(result.Output)
	case "trivy":
		return parseTrivyFindings(result.Output)
	case "semgrep":
		return parseSemgrepFindings(result.Output, targetPath)
	default:
		return nil, fmt.Errorf("unknown scanner: %s", scanner)
	}
}

// =============================================================================
// NUCLEI TOOL
// =============================================================================

// NucleiTool wraps the nuclei vulnerability scanner.
type NucleiTool struct {
	config  *NucleiConfig
	verbose bool
}

func (t *NucleiTool) Name() string {
	return "nuclei"
}

func (t *NucleiTool) Capabilities() []string {
	return []string{"dast", "vulnerability-scan", "web-scan"}
}

func (t *NucleiTool) IsInstalled(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, "nuclei", "-version")
	output, err := cmd.Output()
	if err != nil {
		return false, "", err
	}
	version := strings.TrimSpace(string(output))
	return true, version, nil
}

func (t *NucleiTool) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	args := []string{"-jsonl", "-silent"}

	// Add target
	if opts.Target != "" {
		args = append(args, "-u", opts.Target)
	} else if opts.InputFile != "" {
		args = append(args, "-l", opts.InputFile)
	} else if len(opts.Targets) > 0 {
		// Create temp file with targets
		tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		for _, target := range opts.Targets {
			if _, err := tmpFile.WriteString(target + "\n"); err != nil {
				tmpFile.Close()
				return nil, fmt.Errorf("failed to write to temp file: %w", err)
			}
		}
		tmpFile.Close()
		args = append(args, "-l", tmpFile.Name())
	}

	// Add templates path
	if t.config.TemplatesPath != "" {
		args = append(args, "-t", t.config.TemplatesPath)
	}

	// Add rate limit
	if opts.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
	} else if t.config.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", t.config.RateLimit))
	}

	// Add concurrency
	if opts.Threads > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", opts.Threads))
	} else if t.config.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", t.config.Concurrency))
	}

	// Add severity filter
	if len(t.config.Severity) > 0 {
		args = append(args, "-s", strings.Join(t.config.Severity, ","))
	}

	// Add extra args
	args = append(args, opts.ExtraArgs...)

	if t.verbose {
		fmt.Printf("[nuclei] Running: nuclei %s\n", strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	output, err := cmd.Output()

	result := &ToolResult{
		Tool:     "nuclei",
		Output:   output,
		Duration: time.Since(startTime).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.Success = false
			result.Error = string(exitErr.Stderr)
		} else {
			result.Success = false
			result.Error = err.Error()
		}
		return result, nil
	}

	result.Success = true
	return result, nil
}

// parseNucleiFindings parses nuclei JSONL output using the SDK parser.
// This ensures consistency between agent and SDK parsing logic.
func parseNucleiFindings(output []byte) ([]ctis.Finding, error) {
	// Use SDK parser for consistent parsing with title, description, message fields
	report, err := nuclei.ParseToCTIS(output, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nuclei output: %w", err)
	}

	return report.Findings, nil
}

// =============================================================================
// TRIVY TOOL
// =============================================================================

// TrivyTool wraps the trivy scanner.
type TrivyTool struct {
	config  *TrivyConfig
	verbose bool
}

func (t *TrivyTool) Name() string {
	return "trivy"
}

func (t *TrivyTool) Capabilities() []string {
	return []string{"sca", "container-scan", "config-scan", "vulnerability-scan"}
}

func (t *TrivyTool) IsInstalled(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, "trivy", "version")
	output, err := cmd.Output()
	if err != nil {
		return false, "", err
	}
	// Parse version from output
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return true, strings.TrimPrefix(lines[0], "Version: "), nil
	}
	return true, "", nil
}

func (t *TrivyTool) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Determine scan type from target
	scanType := "fs"
	target := opts.Target
	if strings.HasPrefix(target, "docker:") || strings.HasPrefix(target, "ghcr.io") ||
		strings.HasPrefix(target, "registry.") || strings.Contains(target, ":") && !strings.Contains(target, "/") {
		scanType = "image"
		target = strings.TrimPrefix(target, "docker:")
	} else if strings.HasPrefix(target, "repo:") {
		scanType = "repo"
		target = strings.TrimPrefix(target, "repo:")
	}

	args := []string{scanType, "-f", "json", "-q"}

	// Add cache dir
	if t.config.CacheDir != "" {
		args = append(args, "--cache-dir", t.config.CacheDir)
	}

	// Add severity filter
	if len(t.config.Severity) > 0 {
		args = append(args, "--severity", strings.Join(t.config.Severity, ","))
	}

	// Add ignore file
	if t.config.IgnoreFile != "" {
		args = append(args, "--ignorefile", t.config.IgnoreFile)
	}

	// Add scan types (vuln, config, secret, license)
	if len(t.config.ScanTypes) > 0 {
		args = append(args, "--scanners", strings.Join(t.config.ScanTypes, ","))
	}

	// Add target
	args = append(args, target)

	// Add extra args
	args = append(args, opts.ExtraArgs...)

	if t.verbose {
		fmt.Printf("[trivy] Running: trivy %s\n", strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, "trivy", args...)
	output, err := cmd.Output()

	result := &ToolResult{
		Tool:     "trivy",
		Output:   output,
		Duration: time.Since(startTime).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.Success = false
			result.Error = string(exitErr.Stderr)
		} else {
			result.Success = false
			result.Error = err.Error()
		}
		return result, nil
	}

	result.Success = true
	return result, nil
}

// parseTrivyFindings parses trivy JSON output using the SDK parser.
// This ensures consistency between agent and SDK parsing logic.
func parseTrivyFindings(output []byte) ([]ctis.Finding, error) {
	// Use SDK parser for consistent parsing with title, description, message fields
	report, err := trivy.ParseToCTIS(output, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return report.Findings, nil
}

// =============================================================================
// SEMGREP TOOL
// =============================================================================

// SemgrepTool wraps the semgrep SAST scanner.
type SemgrepTool struct {
	config  *SemgrepConfig
	verbose bool
}

func (t *SemgrepTool) Name() string {
	return "semgrep"
}

func (t *SemgrepTool) Capabilities() []string {
	return []string{"sast", "code-scan", "security-scan"}
}

func (t *SemgrepTool) IsInstalled(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, "semgrep", "--version")
	output, err := cmd.Output()
	if err != nil {
		return false, "", err
	}
	version := strings.TrimSpace(string(output))
	return true, version, nil
}

func (t *SemgrepTool) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Use native JSON for richest metadata (impact, likelihood, vulnerability_class, auto-fix, etc.)
	args := []string{"scan", "--json", "--quiet"}

	// Add config
	if t.config.Config != "" {
		args = append(args, "--config", t.config.Config)
	} else {
		args = append(args, "--config", "auto")
	}

	// Enable dataflow traces for taint tracking paths (SARIF codeFlows)
	// This provides attack path visualization from source to sink
	if t.config.DataflowTraces {
		args = append(args, "--dataflow-traces")
	}

	// Add excludes
	for _, exclude := range t.config.Exclude {
		args = append(args, "--exclude", exclude)
	}

	// Add target
	target := opts.Target
	if target == "" {
		target = "."
	}
	args = append(args, target)

	// Add extra args
	args = append(args, opts.ExtraArgs...)

	if t.verbose {
		fmt.Printf("[semgrep] Running: semgrep %s\n", strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, "semgrep", args...)

	// Semgrep can be chatty on stderr, capture both
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &ToolResult{
		Tool:     "semgrep",
		Output:   stdout.Bytes(),
		Duration: time.Since(startTime).Milliseconds(),
	}

	// Semgrep exits with code 1 when findings are found, which is not an error
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 with findings is normal
			if exitErr.ExitCode() == 1 && stdout.Len() > 0 {
				result.Success = true
				return result, nil
			}
			result.Success = false
			result.Error = stderr.String()
		} else {
			result.Success = false
			result.Error = err.Error()
		}
		return result, nil
	}

	result.Success = true
	return result, nil
}

// parseSemgrepFindings parses semgrep native JSON output using the SDK parser.
// Native JSON provides richest metadata: impact, likelihood, vulnerability_class, auto-fix, etc.
// targetPath is used to read code snippets from source files when Semgrep OSS returns "requires login".
func parseSemgrepFindings(output []byte, targetPath string) ([]ctis.Finding, error) {
	// Use SDK parser for consistent parsing with all metadata fields
	// Pass BasePath so parser can read snippets from source files (fallback for Semgrep OSS)
	opts := &core.ParseOptions{
		BasePath: targetPath,
	}
	report, err := semgrep.ParseToCTIS(output, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	return report.Findings, nil
}

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

// DefaultVulnScanConfig returns a default configuration.
func DefaultVulnScanConfig() *VulnScanConfig {
	homeDir, _ := os.UserHomeDir()

	return &VulnScanConfig{
		Enabled: true,
		Nuclei: NucleiConfig{
			Enabled:       true,
			TemplatesPath: filepath.Join(homeDir, "nuclei-templates"),
			RateLimit:     150,
			Concurrency:   25,
			Severity:      []string{"critical", "high", "medium"},
		},
		Trivy: TrivyConfig{
			Enabled:   true,
			CacheDir:  filepath.Join(homeDir, ".cache", "trivy"),
			Severity:  []string{"CRITICAL", "HIGH", "MEDIUM"},
			ScanTypes: []string{"vuln", "secret"},
		},
		Semgrep: SemgrepConfig{
			Enabled:        true,
			Config:         "auto",
			Exclude:        []string{"vendor", "node_modules", ".git"},
			DataflowTraces: true, // Enable taint tracking for attack path analysis
		},
	}
}
