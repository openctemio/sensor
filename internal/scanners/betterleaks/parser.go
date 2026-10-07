package betterleaks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

// relPath returns a scan-target-relative file path. betterleaks reports paths that
// include the scan root (e.g. "/scan/README.md" for a mounted repo). Persisting
// that leaks the runner's mount point and — worse — makes the secret fingerprint
// depend on where the repo happened to be checked out, so the same secret fails
// to dedupe across scans from different mounts. Strip the known BasePath so the
// path is repo-relative and stable.
func relPath(file string, opts *core.ParseOptions) string {
	if opts == nil || opts.BasePath == "" {
		return file
	}
	base := strings.TrimSuffix(opts.BasePath, "/") + "/"
	return strings.TrimPrefix(file, base)
}

// Parser converts betterleaks (v1) JSON reports to CTIS format. gitleaks
// reports have the same shape and parse too, but are reported under the
// betterleaks tool name: the platform keeps one secret-scanner identity.
type Parser struct{}

// Name returns the parser name.
func (p *Parser) Name() string {
	return core.ScannerBetterleaks
}

// SupportedFormats returns the output formats this parser can handle.
func (p *Parser) SupportedFormats() []string {
	return []string{"json"}
}

// CanParse checks if the parser can handle the given data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as a betterleaks/gitleaks JSON report
	_, err := ParseJSONBytes(data)
	return err == nil
}

// Parse converts a betterleaks JSON report to a CTIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	findings, err := ParseJSONBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse betterleaks output: %w", err)
	}

	// Create CTIS report
	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	// Set tool info
	report.Tool = &ctis.Tool{
		Name:    core.ScannerBetterleaks,
		Vendor:  "Betterleaks",
		InfoURL: "https://github.com/betterleaks/betterleaks",
		Capabilities: []string{
			"secret_detection",
			"api_key_detection",
			"password_detection",
			"private_key_detection",
			"git_history_scan",
		},
	}

	// Set branch info from options (critical for asset auto-creation in ingest)
	if opts != nil && opts.BranchInfo != nil {
		report.Metadata.Branch = opts.BranchInfo
	} else if opts != nil && (opts.Branch != "" || opts.CommitSHA != "") {
		// Legacy: create BranchInfo from individual fields
		report.Metadata.Branch = &ctis.BranchInfo{
			Name:      opts.Branch,
			CommitSHA: opts.CommitSHA,
		}
	}

	// Convert findings
	for i, f := range findings {
		risFinding := p.convertFinding(f, i, opts)
		report.Findings = append(report.Findings, risFinding)
	}

	// File every finding on the scanned repository: the asset opts names
	// (AssetValue, else BranchInfo.RepositoryURL), else the CI job's
	// repository. Findings with none of these are an error, never sent
	// without an asset.
	asset, ok := assetctx.Repository(opts)
	if err := assetctx.BindOrFail(report, asset, ok, "betterleaks"); err != nil {
		return nil, err
	}
	return report, nil
}

// convertFinding converts a betterleaks finding to CTIS finding.
func (p *Parser) convertFinding(f Finding, index int, opts *core.ParseOptions) ctis.Finding {
	file := relPath(f.File, opts)
	title := fmt.Sprintf("%s detected in %s:%d", f.Description, file, f.StartLine)
	finding := ctis.Finding{
		ID:         fmt.Sprintf("finding-%d", index+1),
		Type:       ctis.FindingTypeSecret,
		Title:      title,
		Message:    title,             // Primary display text
		Severity:   ctis.SeverityHigh, // Secrets are always high severity
		Confidence: 90,
		Category:   "Hardcoded Secret",
		RuleID:     f.RuleID,
		RuleName:   f.Description,
		// Description: detailed explanation of the secret type and its risks
		Description: fmt.Sprintf("A %s was detected in the source code. Hardcoded secrets pose a significant security risk as they can be easily extracted from the codebase and used maliciously.", f.Description),
	}

	// Generate or use fingerprint (relative path → stable across checkout dirs).
	// The tool's own fingerprint embeds the file path it was given ("<commit>:
	// <file>:<rule>:<line>" or "<file>:<rule>:<line>"), which is the absolute
	// mount path — so rewrite that path segment to the repo-relative one, else the
	// fingerprint still varies by mount and defeats cross-scan dedupe/auto-resolve.
	// betterleaks v1 builds it exactly as gitleaks did, so a secret both tools
	// report keeps its fingerprint across the switch.
	if f.Fingerprint != "" {
		finding.Fingerprint = strings.Replace(f.Fingerprint, f.File, file, 1)
	} else {
		// SECURITY (CTIS spec 5.2): never hash the raw secret. An unsalted
		// hash of a short secret is reversible by brute force; the masked
		// value carries nothing the masked_value field does not already show.
		finding.Fingerprint = core.GenerateSecretFingerprint(file, f.RuleID, f.StartLine, core.MaskSecret(f.Secret))
	}

	// Set location
	finding.Location = &ctis.FindingLocation{
		Path:        file,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		// SECURITY: the report's Match is the matched text including the raw
		// secret. Never ship it verbatim to the platform — mask the secret
		// inside it the same way MaskedValue is masked.
		Snippet: core.MaskSecretInText(f.Match, f.Secret),
	}

	// Add branch/commit if available
	if opts != nil {
		if opts.Branch != "" {
			finding.Location.Branch = opts.Branch
		}
		if opts.CommitSHA != "" {
			finding.Location.CommitSHA = opts.CommitSHA
		}
	}

	// If the report names a commit, use it
	if f.Commit != "" {
		finding.Location.CommitSHA = f.Commit
	}

	// Set git metadata from the report
	if f.Author != "" {
		finding.Author = f.Author
	}
	if f.Email != "" {
		finding.AuthorEmail = f.Email
	}
	if f.Date != "" {
		// Try to parse date in various formats
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05 -0700",
			"Mon Jan 2 15:04:05 2006 -0700",
		} {
			if t, err := time.Parse(layout, f.Date); err == nil {
				finding.CommitDate = &t
				break
			}
		}
	}

	// Store commit message in properties for reference
	if f.Message != "" {
		if finding.Properties == nil {
			finding.Properties = make(map[string]any)
		}
		finding.Properties["commit_message"] = f.Message
	}

	// Set secret details
	finding.Secret = &ctis.SecretDetails{
		SecretType:  GetSecretType(f.RuleID),
		Service:     GetServiceName(f.RuleID),
		MaskedValue: core.MaskSecret(f.Secret),
		Length:      len(f.Secret),
		Entropy:     f.Entropy,
	}

	// Confidence: the rule's own confidence when betterleaks reports one,
	// else the caller's default, else 90.
	if c, ok := ruleConfidence[f.Confidence()]; ok {
		finding.Confidence = c
	} else if opts != nil && opts.DefaultConfidence > 0 {
		finding.Confidence = opts.DefaultConfidence
	}

	// Add remediation guidance
	finding.Remediation = &ctis.Remediation{
		Recommendation: fmt.Sprintf("Remove the %s from the codebase and rotate/revoke it immediately.", GetSecretType(f.RuleID)),
		Steps: []string{
			"1. Revoke the exposed secret immediately",
			"2. Generate a new secret/credential",
			"3. Update the secret in a secure vault (e.g., HashiCorp Vault, AWS Secrets Manager)",
			"4. Remove the secret from the codebase and git history if necessary",
			"5. Add the file pattern to .gitignore to prevent future commits",
		},
		Effort:       "low",
		FixAvailable: true,
	}

	// Add references
	finding.References = []string{
		"https://github.com/betterleaks/betterleaks",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
	}

	// Add tags
	finding.Tags = []string{
		"secret",
		GetSecretType(f.RuleID),
		GetServiceName(f.RuleID),
	}

	// SECURITY: the description (the title) and the commit message can
	// repeat the raw secret. Mask the secret, the match line and each
	// secret-looking word of the match in every field of the finding.
	ctis.RedactSecretFinding(&finding, f.Secret, f.Match)
	return finding
}

// ruleConfidence maps the confidence betterleaks reports for a rule to a
// CTIS confidence score.
var ruleConfidence = map[string]int{
	"high":   90,
	"medium": 70,
	"low":    40,
}

// ParseToCTIS is a convenience function to parse betterleaks JSON to CTIS.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	parser := &Parser{}
	return parser.Parse(context.Background(), data, opts)
}
