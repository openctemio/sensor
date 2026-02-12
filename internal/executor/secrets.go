package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
	"github.com/openctemio/sdk-go/pkg/scanners/gitleaks"
)

// =============================================================================
// SECRETS EXECUTOR
// =============================================================================

// SecretsExecutor handles secret detection jobs using SDK scanners.
type SecretsExecutor struct {
	mu sync.RWMutex

	// Scanners
	gitleaksScanner *gitleaks.Scanner

	// Configuration
	config  *SecretsConfig
	enabled bool
	verbose bool

	// Pusher for results
	pusher ResultPusher
}

// SecretsConfig configures the secrets executor.
type SecretsConfig struct {
	// Tool enable flags
	GitleaksEnabled   bool
	TrufflehogEnabled bool // Future: add trufflehog support

	// Scan settings
	DefaultTimeout int  // seconds
	ScanGitHistory bool // Scan git history (slower but more thorough)
	Verify         bool // Verify secrets are valid

	// Custom config
	GitleaksConfig string // Path to custom .gitleaks.toml

	// Verbose output
	Verbose bool
}

// DefaultSecretsConfig returns sensible defaults for secret detection.
func DefaultSecretsConfig() *SecretsConfig {
	return &SecretsConfig{
		GitleaksEnabled: true,
		DefaultTimeout:  600, // 10 minutes
		ScanGitHistory:  false,
		Verify:          false,
	}
}

// NewSecretsExecutor creates a new secrets executor.
func NewSecretsExecutor(cfg *SecretsConfig, pusher ResultPusher) *SecretsExecutor {
	if cfg == nil {
		cfg = DefaultSecretsConfig()
	}

	exec := &SecretsExecutor{
		config:  cfg,
		enabled: true,
		verbose: cfg.Verbose,
		pusher:  pusher,
	}

	// Initialize gitleaks scanner
	if cfg.GitleaksEnabled {
		scanner := gitleaks.NewScanner()
		scanner.Verbose = cfg.Verbose
		if cfg.GitleaksConfig != "" {
			scanner.ConfigFile = cfg.GitleaksConfig
		}
		if cfg.DefaultTimeout > 0 {
			scanner.Timeout = time.Duration(cfg.DefaultTimeout) * time.Second
		}
		exec.gitleaksScanner = scanner
	}

	return exec
}

// =============================================================================
// EXECUTOR INTERFACE IMPLEMENTATION
// =============================================================================

func (e *SecretsExecutor) Name() string {
	return "secrets"
}

func (e *SecretsExecutor) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

func (e *SecretsExecutor) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

func (e *SecretsExecutor) Capabilities() []string {
	caps := []string{"secrets", "secret-detection"}

	if e.gitleaksScanner != nil {
		caps = append(caps, e.gitleaksScanner.Capabilities()...)
	}

	return caps
}

func (e *SecretsExecutor) InstalledTools() []string {
	var tools []string

	if e.gitleaksScanner != nil {
		if installed, _, _ := e.gitleaksScanner.IsInstalled(context.Background()); installed {
			tools = append(tools, "gitleaks")
		}
	}

	return tools
}

// =============================================================================
// JOB EXECUTION
// =============================================================================

func (e *SecretsExecutor) Execute(ctx context.Context, job *platform.JobInfo) (*platform.JobResult, error) {
	startTime := time.Now()

	// Parse job payload
	payload, err := e.parsePayload(job)
	if err != nil {
		return e.failResult(job, "invalid payload: "+err.Error(), startTime), err
	}

	// Determine which scanner to use
	scannerName := payload.Scanner
	if scannerName == "" {
		scannerName = "gitleaks" // Default
	}

	// Execute appropriate scanner
	var result *core.SecretResult
	switch scannerName {
	case "gitleaks":
		if e.gitleaksScanner == nil {
			return e.failResult(job, "gitleaks scanner not configured", startTime), ErrToolNotInstalled
		}
		result, err = e.runGitleaks(ctx, payload)
	default:
		return e.failResult(job, fmt.Sprintf("unknown scanner: %s", scannerName), startTime), ErrUnknownJobType
	}

	if err != nil {
		return e.failResult(job, "scan failed: "+err.Error(), startTime), err
	}

	// Convert to CTIS findings
	findings, err := e.convertToFindings(result)
	if err != nil {
		return e.failResult(job, "failed to convert results: "+err.Error(), startTime), err
	}

	// Push results if configured
	if e.pusher != nil && len(findings) > 0 {
		report := &ctis.Report{
			Version: "1.0",
			Metadata: ctis.ReportMetadata{
				ID:         job.ID,
				Timestamp:  time.Now(),
				SourceType: "secrets",
				SourceRef:  job.ID,
			},
			Tool: &ctis.Tool{
				Name:    scannerName,
				Version: e.gitleaksScanner.Version(),
			},
			Findings: findings,
		}

		// Extract repo/branch info from payload for asset creation
		e.enrichReportMetadata(report, payload)

		if pushErr := e.pusher.PushCTIS(ctx, report); pushErr != nil {
			if e.verbose {
				fmt.Printf("[secrets] Warning: failed to push CTIS report: %v\n", pushErr)
			}
		}
	}

	// Build success result
	return &platform.JobResult{
		JobID:         job.ID,
		Status:        "completed",
		CompletedAt:   time.Now(),
		DurationMs:    time.Since(startTime).Milliseconds(),
		FindingsCount: len(findings),
		Metadata: map[string]any{
			"scanner":        scannerName,
			"secrets_found":  len(findings),
			"scan_duration":  result.DurationMs,
			"message":        fmt.Sprintf("Secret scan completed: %d secrets found", len(findings)),
		},
	}, nil
}

// =============================================================================
// SCANNER EXECUTION
// =============================================================================

func (e *SecretsExecutor) runGitleaks(ctx context.Context, payload *secretsPayload) (*core.SecretResult, error) {
	opts := &core.SecretScanOptions{
		TargetDir:  payload.Target,
		ConfigFile: e.config.GitleaksConfig,
		NoGit:      !e.config.ScanGitHistory,
		Verify:     e.config.Verify,
		Verbose:    e.verbose,
	}

	if payload.Options.ConfigFile != "" {
		opts.ConfigFile = payload.Options.ConfigFile
	}
	if len(payload.Options.Exclude) > 0 {
		opts.Exclude = payload.Options.Exclude
	}
	if payload.Options.NoGit {
		opts.NoGit = true
	}
	if payload.Options.Verify {
		opts.Verify = true
	}

	return e.gitleaksScanner.Scan(ctx, payload.Target, opts)
}

// =============================================================================
// RESULT CONVERSION
// =============================================================================

func (e *SecretsExecutor) convertToFindings(result *core.SecretResult) ([]ctis.Finding, error) {
	var findings []ctis.Finding

	for _, secret := range result.Secrets {
		finding := ctis.Finding{
			Type:        ctis.FindingTypeSecret,
			Title:       fmt.Sprintf("%s detected", secret.SecretType),
			Description: fmt.Sprintf("Potential %s secret found in %s", secret.SecretType, secret.File),
			Severity:    mapSecretSeverity(secret.SecretType),
			RuleID:      secret.RuleID,
			Category:    "secret",
			AssetValue:  secret.File,
			Location: &ctis.FindingLocation{
				Path:        secret.File,
				StartLine:   secret.StartLine,
				EndLine:     secret.EndLine,
				StartColumn: secret.StartColumn,
				EndColumn:   secret.EndColumn,
				Snippet:     secret.Match,
			},
			Secret: &ctis.SecretDetails{
				SecretType:  secret.SecretType,
				Service:     secret.Service,
				MaskedValue: secret.MaskedValue,
				Entropy:     secret.Entropy,
			},
			Fingerprint: secret.Fingerprint,
		}

		// Add git attribution if available
		if secret.Author != "" || secret.Commit != "" {
			finding.Properties = map[string]any{
				"author": secret.Author,
				"commit": secret.Commit,
				"date":   secret.Date,
			}
		}

		// Add verification status
		if secret.Valid != nil {
			finding.Secret.Valid = secret.Valid
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// mapSecretSeverity maps secret type to severity level.
func mapSecretSeverity(secretType string) ctis.Severity {
	// High severity for credentials that provide direct access
	highSeverity := map[string]bool{
		"aws-access-key":       true,
		"aws-secret-key":       true,
		"github-token":         true,
		"github-pat":           true,
		"gitlab-token":         true,
		"private-key":          true,
		"ssh-private-key":      true,
		"rsa-private-key":      true,
		"database-password":    true,
		"stripe-api-key":       true,
		"twilio-auth-token":    true,
		"sendgrid-api-key":     true,
		"slack-webhook":        true,
		"jwt-secret":           true,
		"encryption-key":       true,
	}

	// Medium severity for less critical tokens
	mediumSeverity := map[string]bool{
		"api-key":           true,
		"generic-api-key":   true,
		"slack-token":       true,
		"npm-token":         true,
		"pypi-token":        true,
		"nuget-api-key":     true,
	}

	if highSeverity[secretType] {
		return ctis.SeverityHigh
	}
	if mediumSeverity[secretType] {
		return ctis.SeverityMedium
	}
	return ctis.SeverityMedium // Default to medium for unknown types
}

// =============================================================================
// HELPERS
// =============================================================================

type secretsPayload struct {
	Scanner string `json:"scanner"`
	Target  string `json:"target"`
	Options struct {
		ConfigFile string   `json:"config_file"`
		Exclude    []string `json:"exclude"`
		NoGit      bool     `json:"no_git"`
		Verify     bool     `json:"verify"`
	} `json:"options"`

	// Repository context for asset creation
	RepoURL   string `json:"repo_url"`
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
	IsDefault bool   `json:"is_default_branch"`
}

func (e *SecretsExecutor) parsePayload(job *platform.JobInfo) (*secretsPayload, error) {
	data, err := json.Marshal(job.Payload)
	if err != nil {
		return nil, err
	}

	var payload secretsPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if payload.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	return &payload, nil
}

func (e *SecretsExecutor) failResult(job *platform.JobInfo, message string, startTime time.Time) *platform.JobResult {
	return &platform.JobResult{
		JobID:       job.ID,
		Status:      "failed",
		Error:       message,
		CompletedAt: time.Now(),
		DurationMs:  time.Since(startTime).Milliseconds(),
	}
}

// enrichReportMetadata adds repo/branch info to the report for asset creation.
// This is critical for the ingest service to properly link findings to assets.
func (e *SecretsExecutor) enrichReportMetadata(report *ctis.Report, payload *secretsPayload) {
	// Add branch info if available (for auto-create asset in ingest)
	if payload.RepoURL != "" || payload.Branch != "" {
		report.Metadata.Branch = &ctis.BranchInfo{
			RepositoryURL:   payload.RepoURL,
			Name:            payload.Branch,
			CommitSHA:       payload.CommitSHA,
			IsDefaultBranch: payload.IsDefault,
		}

		if e.verbose {
			fmt.Printf("[secrets] Added branch info to report: repo=%s branch=%s\n", payload.RepoURL, payload.Branch)
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

		if e.verbose {
			fmt.Printf("[secrets] Added asset to report: %s\n", payload.RepoURL)
		}
	}
}
