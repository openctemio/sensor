package nuclei

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

// Parser converts Nuclei output to CTIS format.
type Parser struct {
	Verbose bool
}

// NewParser creates a new Nuclei parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts Nuclei JSON Lines output to CTIS Report.
func (p *Parser) Parse(data []byte, target string) (*ctis.Report, error) {
	return p.ParseWithOptions(data, target, nil)
}

// ParseWithOptions converts Nuclei JSON Lines output to CTIS Report with options.
func (p *Parser) ParseWithOptions(data []byte, target string, opts *core.ParseOptions) (*ctis.Report, error) {
	results, err := p.parseJSONLines(data)
	if err != nil {
		return nil, err
	}

	return p.toCTISReportWithOptions(results, target, opts), nil
}

// ParseResults converts parsed Nuclei results to CTIS Report.
func (p *Parser) ParseResults(results []Result, target string) *ctis.Report {
	return p.toCTISReportWithOptions(results, target, nil)
}

// ParseResultsWithOptions converts parsed Nuclei results to CTIS Report with options.
func (p *Parser) ParseResultsWithOptions(results []Result, target string, opts *core.ParseOptions) *ctis.Report {
	return p.toCTISReportWithOptions(results, target, opts)
}

// parseJSONLines parses Nuclei's JSON Lines output format.
func (p *Parser) parseJSONLines(data []byte) ([]Result, error) {
	var results []Result

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Increase buffer size for large responses
	const maxCapacity = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var result Result
		if err := json.Unmarshal(line, &result); err != nil {
			if p.Verbose {
				fmt.Printf("[nuclei-parser] Warning: Failed to parse line: %v\n", err)
			}
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading output: %w", err)
	}

	return results, nil
}

// toCTISReportWithOptions converts Nuclei results to CTIS Report format with options.
func (p *Parser) toCTISReportWithOptions(results []Result, _ string, opts *core.ParseOptions) *ctis.Report {
	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

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

	report.Tool = &ctis.Tool{
		Name:         "nuclei",
		Vendor:       "ProjectDiscovery",
		InfoURL:      "https://github.com/projectdiscovery/nuclei",
		Capabilities: []string{"dast", "vulnerability_scanning", "misconfiguration_detection"},
	}

	// Track unique assets
	assetMap := make(map[string]string) // host -> asset ID

	for i, result := range results {
		// Create or get asset for this result. A result naming no host,
		// URL or IP falls back to the scan target the caller named; with
		// neither it has no asset, and ReportParser.Parse / ParseToCTIS
		// reject the report (ctis.CheckFindingAssets).
		assetID := p.getOrCreateAsset(report, result, assetMap)
		if assetID == "" && opts != nil && strings.TrimSpace(opts.AssetValue) != "" {
			assetID = p.getOrCreateTargetAsset(report, opts, assetMap)
		}

		// Create finding
		finding := p.toCTISFinding(result, assetID, i)
		report.Findings = append(report.Findings, finding)
	}

	return report
}

// getOrCreateAsset creates or retrieves an asset for the result.
func (p *Parser) getOrCreateAsset(report *ctis.Report, result Result, assetMap map[string]string) string {
	// Determine asset key (host or URL)
	key := result.Host
	if result.URL != "" {
		key = result.URL
	}

	// Check if asset already exists
	if assetID, exists := assetMap[key]; exists {
		return assetID
	}

	assetType := ctis.AssetTypeDomain
	assetValue := result.Host

	// Determine asset type based on result
	if result.IP != "" {
		assetType = ctis.AssetTypeIPAddress
		assetValue = result.IP
	} else if result.URL != "" {
		assetType = ctis.AssetTypeService
		assetValue = result.URL
	}

	// An asset with no value is not stored by ingest; a finding on it
	// would be rejected. Leave such a result without an asset.
	if strings.TrimSpace(assetValue) == "" {
		return ""
	}

	// Create new asset
	assetID := fmt.Sprintf("asset-%d", len(report.Assets))
	assetMap[key] = assetID

	asset := ctis.Asset{
		ID:         assetID,
		Type:       assetType,
		Value:      assetValue,
		Name:       key,
		Confidence: 90,
		Properties: make(ctis.Properties),
	}

	// Add technical details
	if result.Port != "" {
		asset.Properties["port"] = result.Port
	}
	if result.IP != "" {
		asset.Properties["ip"] = result.IP
	}

	report.Assets = append(report.Assets, asset)
	return assetID
}

// getOrCreateTargetAsset returns the asset for the scan target opts names
// (AssetValue/AssetType), adding it on first use.
func (p *Parser) getOrCreateTargetAsset(report *ctis.Report, opts *core.ParseOptions, assetMap map[string]string) string {
	key := "\x00target"
	if assetID, exists := assetMap[key]; exists {
		return assetID
	}
	assetType := opts.AssetType
	if assetType == "" {
		assetType, _ = assetctx.HostAsset(opts.AssetValue)
	}
	if assetType == "" {
		assetType = ctis.AssetTypeDomain
	}
	assetID := fmt.Sprintf("asset-%d", len(report.Assets))
	assetMap[key] = assetID
	report.Assets = append(report.Assets, ctis.Asset{
		ID:         assetID,
		Type:       assetType,
		Value:      opts.AssetValue,
		Name:       opts.AssetValue,
		Properties: ctis.Properties{"source": "parse_options"},
	})
	return assetID
}

// toCTISFinding converts a Nuclei result to CTIS Finding.
func (p *Parser) toCTISFinding(result Result, assetRef string, index int) ctis.Finding {
	findingID := fmt.Sprintf("finding-%d", index)

	// Determine finding type
	findingType := ctis.FindingTypeVulnerability
	if containsAny(result.Info.Tags, "misconfig", "config", "exposure") {
		findingType = ctis.FindingTypeMisconfiguration
	}

	// Map severity
	severity := ctis.Severity(GetCTISSeverity(result.Info.Severity))

	// Build title
	title := result.Info.Name
	if title == "" {
		title = result.TemplateID
	}

	finding := ctis.Finding{
		ID:          findingID,
		Type:        findingType,
		Title:       title,
		Description: result.Info.Description,
		Message:     title, // Primary display text
		Severity:    severity,
		Confidence:  85, // Nuclei templates are generally reliable
		Category:    getCategoryFromTags(result.Info.Tags),
		RuleID:      result.TemplateID,
		RuleName:    result.Info.Name,
		AssetRef:    assetRef,
		Tags:        result.Info.Tags,
		References:  result.Info.Reference,
		Fingerprint: p.generateFingerprint(result),
		Properties:  make(ctis.Properties),
	}

	// Set location based on matched URL
	if result.Matched != "" || result.URL != "" {
		location := result.Matched
		if location == "" {
			location = result.URL
		}
		finding.Location = &ctis.FindingLocation{
			// The matched URL can carry userinfo or a token in its query.
			// The fingerprint uses the raw value, so identity is unchanged.
			Path: redactURL(location),
		}
	}

	// Add vulnerability details if classification exists
	if result.Info.Classification != nil {
		finding.Vulnerability = &ctis.VulnerabilityDetails{}

		if len(result.Info.Classification.CVEId) > 0 {
			finding.Vulnerability.CVEID = result.Info.Classification.CVEId[0]
		}
		if len(result.Info.Classification.CWEId) > 0 {
			finding.Vulnerability.CWEIDs = result.Info.Classification.CWEId
			finding.Vulnerability.CWEID = result.Info.Classification.CWEId[0]
		}
		if result.Info.Classification.CVSSScore > 0 {
			finding.Vulnerability.CVSSScore = result.Info.Classification.CVSSScore
			finding.Vulnerability.CVSSVector = result.Info.Classification.CVSSMetrics
		}
		if result.Info.Classification.EPSSScore > 0 {
			finding.Vulnerability.EPSSScore = result.Info.Classification.EPSSScore
			finding.Vulnerability.EPSSPercentile = result.Info.Classification.EPSSPercentile
		}
		if result.Info.Classification.CPEURI != "" {
			finding.Vulnerability.CPE = result.Info.Classification.CPEURI
		}
	}

	// Add remediation if available
	if result.Info.Remediation != "" {
		finding.Remediation = &ctis.Remediation{
			Recommendation: result.Info.Remediation,
		}
	}

	// Store additional data in properties. SECURITY (CTIS spec 4.8): the
	// request, response and curl command carry credentials (the scan's own
	// headers, a token an exposure template found) and extracted results are
	// what the template was written to find. Redact, then cap; see redact.go.
	if result.Request != "" {
		finding.Properties["request"] = capText(redactText(result.Request, result.ExtractedResults), maxRequestEvidence)
	}
	if result.Response != "" {
		finding.Properties["response"] = capText(redactResponse(result.Response, result.Info.Tags, result.ExtractedResults), maxResponseEvidence)
	}
	if result.CurlCommand != "" {
		finding.Properties["curl_command"] = capText(redactText(result.CurlCommand, result.ExtractedResults), maxCurlEvidence)
	}
	if len(result.ExtractedResults) > 0 {
		finding.Properties["extracted_results"] = maskExtracted(result.ExtractedResults)
	}
	if result.MatcherName != "" {
		finding.Properties["matcher_name"] = result.MatcherName
	}
	if result.Interaction != nil {
		finding.Properties["interaction"] = map[string]any{
			"protocol":       result.Interaction.Protocol,
			"unique_id":      result.Interaction.UniqueID,
			"remote_address": result.Interaction.RemoteAddress,
		}
	}

	// Set author if available
	if len(result.Info.Author) > 0 {
		finding.Author = strings.Join(result.Info.Author, ", ")
	}

	now := time.Now()
	finding.FirstSeenAt = &now
	finding.LastSeenAt = &now

	return finding
}

// generateFingerprint creates a unique fingerprint for a finding.
func (p *Parser) generateFingerprint(result Result) string {
	// Combine key identifying fields
	data := fmt.Sprintf("%s|%s|%s|%s",
		result.TemplateID,
		result.Host,
		result.Matched,
		result.MatcherName,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// getCategoryFromTags extracts the primary category from tags.
func getCategoryFromTags(tags []string) string {
	// Priority order for categories
	priorities := []string{
		"cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi",
		"auth-bypass", "takeover", "exposure", "misconfig",
		"default-login", "creds", "injection",
	}

	for _, priority := range priorities {
		for _, tag := range tags {
			if strings.EqualFold(tag, priority) {
				return tag
			}
		}
	}

	// Return first tag if no priority match
	if len(tags) > 0 {
		return tags[0]
	}
	return "vulnerability"
}

// containsAny checks if any of the search strings exist in the slice.
func containsAny(slice []string, searches ...string) bool {
	for _, s := range slice {
		for _, search := range searches {
			if strings.EqualFold(s, search) {
				return true
			}
		}
	}
	return false
}

// ParseToCTIS is a convenience function to parse Nuclei JSON Lines to CTIS format.
// This provides a consistent API with other scanner parsers (e.g., semgrep.ParseToCTIS).
// Note: target can be extracted from opts.AssetValue or left empty if not needed.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	parser := NewParser()
	target := ""
	if opts != nil && opts.AssetValue != "" {
		target = opts.AssetValue
	}
	report, err := parser.ParseWithOptions(data, target, opts)
	if err != nil {
		return nil, err
	}
	if err := ctis.CheckFindingAssets(report); err != nil {
		return nil, err
	}
	return report, nil
}
