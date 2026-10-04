package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

// Parser converts Trivy JSON output to CTIS format.
type Parser struct {
	// Configuration
	Verbose bool
}

// NewParser creates a new Trivy parser.
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "trivy"
}

// SupportedFormats returns supported output formats.
func (p *Parser) SupportedFormats() []string {
	return []string{"json", "trivy"}
}

// CanParse checks if this parser can handle the data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as Trivy JSON
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return false
	}

	// Check for Trivy-specific fields
	return report.SchemaVersion > 0 || report.ArtifactType != "" || len(report.Results) > 0
}

// Parse converts Trivy JSON output to CTIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	var trivyReport Report
	if err := json.Unmarshal(data, &trivyReport); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Create CTIS report
	report := ctis.NewReport()

	// Set metadata
	report.Metadata = ctis.ReportMetadata{
		ID:         fmt.Sprintf("trivy-%d", time.Now().Unix()),
		Timestamp:  time.Now(),
		SourceType: "scanner",
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

	// Set tool info
	report.Tool = &ctis.Tool{
		Name:         "trivy",
		Vendor:       "Aqua Security",
		Capabilities: p.inferCapabilities(&trivyReport),
	}

	// Parse results
	for _, result := range trivyReport.Results {
		// Parse vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := p.parseVulnerability(&result, &vuln, opts)
			report.Findings = append(report.Findings, finding)
		}

		// Parse misconfigurations
		for _, misconfig := range result.Misconfigurations {
			finding := p.parseMisconfiguration(&result, &misconfig, opts)
			report.Findings = append(report.Findings, finding)
		}

		// Parse secrets
		for _, secret := range result.Secrets {
			finding := p.parseSecret(&result, &secret, opts)
			report.Findings = append(report.Findings, finding)
		}

		// Parse packages (SBOM)
		for _, pkg := range result.Packages {
			dep := p.parsePackage(&result, &pkg, opts)
			report.Dependencies = append(report.Dependencies, dep)
		}
	}

	if p.Verbose {
		fmt.Printf("[trivy-parser] Parsed %d findings from %s\n", len(report.Findings), trivyReport.ArtifactName)
	}

	// File every finding on one asset (see createAssetFromContext). Findings
	// with no asset are an error, never sent without one.
	asset := p.createAssetFromContext(&trivyReport, opts)
	if asset == nil {
		if err := assetctx.BindOrFail(report, ctis.Asset{}, false, "trivy"); err != nil {
			return nil, err
		}
		return report, nil
	}
	assetctx.Bind(report, *asset)
	return report, nil
}

// createAssetFromContext returns the asset a Trivy report's findings belong
// to: the asset opts names (AssetValue, else BranchInfo.RepositoryURL), else
// the artifact when it is an asset by itself (the image of an image scan,
// the remote repository of a repo scan), else the CI job's repository. It
// returns nil when none applies: the local path of a filesystem scan is not
// an asset, and filing findings on it (as this parser once did) mixed every
// checkout path into fake repositories.
func (p *Parser) createAssetFromContext(report *Report, opts *core.ParseOptions) *ctis.Asset {
	asset, ok := assetctx.Explicit(opts)
	if !ok {
		asset, ok = assetctx.TrivyArtifact(report.ArtifactType, report.ArtifactName)
		if ok && opts != nil && opts.AssetID != "" {
			asset.ID = opts.AssetID
		}
	}
	if !ok {
		id := ""
		if opts != nil {
			id = opts.AssetID
		}
		asset, ok = assetctx.CI(id)
	}
	if !ok {
		return nil
	}
	if report.Metadata.OS != nil && report.Metadata.OS.Family != "" {
		asset.Tags = append(asset.Tags, report.Metadata.OS.Family)
	}
	return &asset
}

// parseVulnerability converts Trivy vulnerability to CTIS finding.
func (p *Parser) parseVulnerability(result *Result, vuln *Vulnerability, opts *core.ParseOptions) ctis.Finding {
	// Get CVSS info
	cvssScore, cvssVector, cvssSource := GetBestCVSSScore(vuln.CVSS)

	// Generate fingerprint
	fingerprint := p.generateFingerprint(vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, result.Target)

	title := p.buildVulnTitle(vuln)
	finding := ctis.Finding{
		ID:          vuln.VulnerabilityID,
		Type:        ctis.FindingTypeVulnerability,
		Title:       title,
		Description: vuln.Description,
		Message:     title, // Primary display text
		Severity:    ctis.Severity(GetCTISSeverity(vuln.Severity)),
		Confidence:  100, // Trivy is deterministic
		RuleID:      vuln.VulnerabilityID,
		RuleName:    vuln.Title,
		Category:    "vulnerability",
		Fingerprint: fingerprint,
	}

	// Set location
	if vuln.PkgPath != "" {
		finding.Location = &ctis.FindingLocation{
			Path: vuln.PkgPath,
		}
	} else if result.Target != "" {
		finding.Location = &ctis.FindingLocation{
			Path: result.Target,
		}
	}

	// Set vulnerability details
	finding.Vulnerability = &ctis.VulnerabilityDetails{
		CVEID:           vuln.VulnerabilityID,
		CWEIDs:          vuln.CweIDs,
		CVSSVersion:     p.getCVSSVersion(cvssVector),
		CVSSScore:       cvssScore,
		CVSSVector:      cvssVector,
		CVSSSource:      cvssSource,
		Package:         vuln.PkgName,
		AffectedVersion: vuln.InstalledVersion,
		FixedVersion:    vuln.FixedVersion,
		Ecosystem:       result.Type,
		PURL:            buildPURL(result.Type, vuln.PkgName, vuln.InstalledVersion),
		SeveritySource:  vuln.SeveritySource,
		VendorSeverity:  vuln.VendorSeverity,
		VulnStatus:      vuln.Status,
	}

	// Set data source if available
	if vuln.DataSource != nil {
		finding.Vulnerability.DataSource = &ctis.VulnDataSource{
			ID:   vuln.DataSource.ID,
			Name: vuln.DataSource.Name,
			URL:  vuln.DataSource.URL,
		}
	}

	// Set container layer info if available (for image scans)
	if vuln.Layer != nil {
		finding.Vulnerability.Layer = &ctis.ContainerLayer{
			Digest: vuln.Layer.Digest,
			DiffID: vuln.Layer.DiffID,
		}
	}

	// Set dates if available
	if vuln.PublishedDate != "" {
		if t, err := time.Parse(time.RFC3339, vuln.PublishedDate); err == nil {
			finding.Vulnerability.PublishedAt = &t
		}
	}
	if vuln.LastModifiedDate != "" {
		if t, err := time.Parse(time.RFC3339, vuln.LastModifiedDate); err == nil {
			finding.Vulnerability.ModifiedAt = &t
		}
	}

	// Set references
	if vuln.PrimaryURL != "" {
		finding.References = append(finding.References, vuln.PrimaryURL)
	}
	finding.References = append(finding.References, vuln.References...)

	// Set remediation
	if vuln.FixedVersion != "" {
		finding.Remediation = &ctis.Remediation{
			Recommendation: fmt.Sprintf("Upgrade %s from %s to %s", vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion),
			FixAvailable:   true,
		}
	}

	// Set tags
	finding.Tags = []string{"sca", result.Type}
	if vuln.Status != "" {
		finding.Tags = append(finding.Tags, vuln.Status)
	}

	return finding
}

// parseMisconfiguration converts Trivy misconfiguration to CTIS finding.
func (p *Parser) parseMisconfiguration(result *Result, misconfig *Misconfiguration, opts *core.ParseOptions) ctis.Finding {
	// Skip PASS status
	if misconfig.Status == "PASS" {
		return ctis.Finding{}
	}

	fingerprint := p.generateFingerprint(misconfig.ID, result.Target, misconfig.Type, misconfig.Message)

	finding := ctis.Finding{
		ID:          misconfig.ID,
		Type:        ctis.FindingTypeMisconfiguration,
		Title:       misconfig.Title,
		Description: misconfig.Description,
		Message:     misconfig.Title, // Primary display text
		Severity:    ctis.Severity(GetCTISSeverity(misconfig.Severity)),
		Confidence:  100,
		RuleID:      misconfig.ID,
		RuleName:    misconfig.Title,
		Category:    "misconfiguration",
		Fingerprint: fingerprint,
	}

	// Set location
	if misconfig.CauseMetadata.StartLine > 0 {
		finding.Location = &ctis.FindingLocation{
			Path:      result.Target,
			StartLine: misconfig.CauseMetadata.StartLine,
			EndLine:   misconfig.CauseMetadata.EndLine,
		}

		// Add code snippet
		if len(misconfig.CauseMetadata.Code.Lines) > 0 {
			var snippet strings.Builder
			for _, line := range misconfig.CauseMetadata.Code.Lines {
				if line.IsCause {
					snippet.WriteString(line.Content)
					snippet.WriteString("\n")
				}
			}
			finding.Location.Snippet = strings.TrimSuffix(snippet.String(), "\n")
		}
	} else {
		finding.Location = &ctis.FindingLocation{
			Path: result.Target,
		}
	}

	// Set misconfiguration details
	finding.Misconfiguration = &ctis.MisconfigurationDetails{
		PolicyID:     misconfig.ID,
		PolicyName:   misconfig.Title,
		AVDID:        misconfig.AVDID,
		ResourceType: misconfig.Type,
		ResourceName: misconfig.CauseMetadata.Resource,
		Provider:     misconfig.CauseMetadata.Provider,
		Service:      misconfig.CauseMetadata.Service,
		Namespace:    misconfig.Namespace,
		Query:        misconfig.Query,
		Cause:        misconfig.Message,
	}

	// Set references
	if misconfig.PrimaryURL != "" {
		finding.References = append(finding.References, misconfig.PrimaryURL)
	}
	finding.References = append(finding.References, misconfig.References...)

	// Set remediation
	if misconfig.Resolution != "" {
		finding.Remediation = &ctis.Remediation{
			Recommendation: misconfig.Resolution,
		}
	}

	// Append message to description if both exist and are different
	// Message contains the specific cause, while Description contains general explanation
	if misconfig.Message != "" && misconfig.Message != misconfig.Description {
		if finding.Description != "" {
			finding.Description = finding.Description + "\n\nCause: " + misconfig.Message
		} else {
			finding.Description = misconfig.Message
		}
	}

	// Set tags
	finding.Tags = []string{"iac", misconfig.Type}
	if misconfig.CauseMetadata.Provider != "" {
		finding.Tags = append(finding.Tags, misconfig.CauseMetadata.Provider)
	}

	return finding
}

// parseSecret converts Trivy secret to CTIS finding.
func (p *Parser) parseSecret(result *Result, secret *Secret, opts *core.ParseOptions) ctis.Finding {
	fingerprint := p.generateFingerprint(secret.RuleID, result.Target, fmt.Sprintf("%d", secret.StartLine), secret.Match)

	finding := ctis.Finding{
		ID:          fmt.Sprintf("%s-%d", secret.RuleID, secret.StartLine),
		Type:        ctis.FindingTypeSecret,
		Title:       secret.Title,
		Description: fmt.Sprintf("Secret detected: %s", secret.Category),
		Message:     secret.Title, // Primary display text
		Severity:    ctis.Severity(GetCTISSeverity(secret.Severity)),
		Confidence:  100,
		RuleID:      secret.RuleID,
		RuleName:    secret.Title,
		Category:    "secret",
		Fingerprint: fingerprint,
	}

	// Set location
	finding.Location = &ctis.FindingLocation{
		Path:      result.Target,
		StartLine: secret.StartLine,
		EndLine:   secret.EndLine,
	}

	// Add code snippet
	if len(secret.Code.Lines) > 0 {
		var snippet strings.Builder
		for _, line := range secret.Code.Lines {
			snippet.WriteString(line.Content)
			snippet.WriteString("\n")
		}
		finding.Location.Snippet = strings.TrimSuffix(snippet.String(), "\n")
	}

	// Set secret details
	finding.Secret = &ctis.SecretDetails{
		SecretType:  secret.Category,
		MaskedValue: maskSecret(secret.Match),
		Length:      len(secret.Match),
	}

	// Set tags
	finding.Tags = []string{"secret", secret.Category}

	return finding
}

// parsePackage converts Trivy package to CTIS dependency.
func (p *Parser) parsePackage(result *Result, pkg *Package, _ *core.ParseOptions) ctis.Dependency {
	id := p.generateFingerprint("pkg", result.Target, pkg.Name, pkg.Version)

	dep := ctis.Dependency{
		ID:           id,
		Name:         pkg.Name,
		Version:      pkg.Version,
		PURL:         pkg.Identifier.PURL,
		UID:          pkg.Identifier.UID,
		Licenses:     pkg.Licenses,
		Relationship: pkg.Relationship,
		DependsOn:    pkg.DependsOn,
	}

	// Determine ecosystem
	if pkg.Identifier.PURL != "" {
		// pkg:golang/github.com/foo/bar -> golang
		if parts := strings.Split(pkg.Identifier.PURL, "/"); len(parts) > 0 {
			if typeParams := strings.Split(parts[0], ":"); len(typeParams) > 1 {
				dep.Ecosystem = typeParams[1]
			}
		}
	}
	if dep.Ecosystem == "" {
		dep.Ecosystem = result.Type
	}

	// Set path from file path or target
	if pkg.FilePath != "" {
		dep.Path = pkg.FilePath
	} else if pkg.PkgPath != "" {
		dep.Path = pkg.PkgPath
	} else {
		dep.Path = result.Target
	}

	// Set locations array from Trivy locations
	if len(pkg.Locations) > 0 {
		dep.Locations = make([]ctis.DependencyLocation, 0, len(pkg.Locations))
		for _, loc := range pkg.Locations {
			dep.Locations = append(dep.Locations, ctis.DependencyLocation{
				Path:      dep.Path,
				StartLine: loc.StartLine,
				EndLine:   loc.EndLine,
			})
		}
	}

	// Also set legacy Location field for backward compatibility
	dep.Location = &ctis.FindingLocation{
		Path: dep.Path,
	}
	if len(pkg.Locations) > 0 {
		dep.Location.StartLine = pkg.Locations[0].StartLine
		dep.Location.EndLine = pkg.Locations[0].EndLine
	}

	return dep
}

// buildVulnTitle builds a title for vulnerability.
func (p *Parser) buildVulnTitle(vuln *Vulnerability) string {
	if vuln.Title != "" {
		return fmt.Sprintf("%s: %s", vuln.VulnerabilityID, vuln.Title)
	}
	return fmt.Sprintf("%s in %s %s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion)
}

// generateFingerprint generates a unique fingerprint.
func (p *Parser) generateFingerprint(parts ...string) string {
	data := strings.Join(parts, ":")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16])
}

// getCVSSVersion extracts CVSS version from vector.
func (p *Parser) getCVSSVersion(vector string) string {
	if strings.HasPrefix(vector, "CVSS:3.1") {
		return "3.1"
	}
	if strings.HasPrefix(vector, "CVSS:3.0") {
		return "3.0"
	}
	if strings.Contains(vector, "AV:") && !strings.HasPrefix(vector, "CVSS:") {
		return "2.0"
	}
	return ""
}

// inferCapabilities infers tool capabilities from report.
func (p *Parser) inferCapabilities(report *Report) []string {
	caps := make(map[string]bool)

	for _, result := range report.Results {
		if len(result.Vulnerabilities) > 0 {
			caps["vulnerability"] = true
			caps["sca"] = true
		}
		if len(result.Misconfigurations) > 0 {
			caps["misconfiguration"] = true
			caps["iac"] = true
		}
		if len(result.Secrets) > 0 {
			caps["secret_detection"] = true
		}
		if len(result.Licenses) > 0 {
			caps["license_compliance"] = true
		}
	}

	result := make([]string, 0, len(caps))
	for cap := range caps {
		result = append(result, cap)
	}
	return result
}

// maskSecret masks a secret value: core.MaskSecret, so every scanner masks
// alike (CTIS spec 4.8).
func maskSecret(value string) string {
	return core.MaskSecret(value)
}

// ParseJSONBytes parses Trivy JSON output from bytes.
func ParseJSONBytes(data []byte) (*Report, error) {
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON: %w", err)
	}
	return &report, nil
}

// ParseToCTIS is a convenience function to parse Trivy JSON to CTIS format.
// This provides a consistent API with other scanner parsers (e.g., semgrep.ParseToCTIS).
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	parser := NewParser()
	return parser.Parse(context.Background(), data, opts)
}
