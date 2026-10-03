package semgrep

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/assetctx"
)

// Parser converts semgrep output to CTIS format.
type Parser struct{}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "semgrep"
}

// SupportedFormats returns the output formats this parser can handle.
func (p *Parser) SupportedFormats() []string {
	return []string{"json"}
}

// CanParse checks if the parser can handle the given data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as semgrep JSON
	report, err := ParseJSONBytes(data)
	if err != nil {
		return false
	}
	// Check for semgrep-specific fields to avoid matching trivy/other JSON formats
	// Semgrep results have check_id, path, start, end, extra fields
	// If Results is empty but no errors, it might still be valid semgrep output
	if len(report.Results) > 0 {
		// Check if first result has semgrep-specific fields
		r := report.Results[0]
		return r.CheckID != "" && r.Path != ""
	}
	// Empty results with version field is likely semgrep
	return report.Version != ""
}

// Parse converts semgrep JSON output to CTIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	// Parse semgrep report
	semgrepReport, err := ParseJSONBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	// Create CTIS report
	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	// Set tool info
	report.Tool = &ctis.Tool{
		Name:   "semgrep",
		Vendor: "Semgrep Inc.",
		Capabilities: []string{
			"sast",
			"code_analysis",
			"vulnerability_detection",
			"code_quality",
			"taint_tracking",
		},
	}
	if semgrepReport.Version != "" {
		report.Tool.Version = semgrepReport.Version
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
	for i, r := range semgrepReport.Results {
		risFinding := p.convertResult(r, i, opts)
		report.Findings = append(report.Findings, risFinding)
	}

	// File every finding on the scanned repository: the asset opts names
	// (AssetValue, else BranchInfo.RepositoryURL), else the CI job's
	// repository. Findings with none of these are an error, never sent
	// without an asset.
	asset, ok := assetctx.Repository(opts)
	if err := assetctx.BindOrFail(report, asset, ok, "semgrep"); err != nil {
		return nil, err
	}
	return report, nil
}

// convertResult converts a semgrep result to CTIS finding.
func (p *Parser) convertResult(r Result, index int, opts *core.ParseOptions) ctis.Finding {
	// Build human-readable title from check ID
	// e.g., "python.lang.security.audit.eval-injection" -> "Eval Injection"
	humanTitle := SlugToNormalText(r.CheckID)

	finding := ctis.Finding{
		ID:                 fmt.Sprintf("finding-%d", index+1),
		Type:               ctis.FindingTypeVulnerability,
		Title:              humanTitle,      // Short title for list display
		Description:        "",              // Don't duplicate message - Semgrep only has one text field
		Message:            r.Extra.Message, // Primary message from semgrep (vulnerability explanation)
		Severity:           ctis.Severity(r.GetSeverity()),
		Confidence:         r.GetConfidence(),
		Impact:             r.GetImpact(),
		Likelihood:         r.GetLikelihood(),
		Category:           r.GetCategory(),
		VulnerabilityClass: r.GetVulnerabilityClass(),
		Subcategory:        r.GetSubcategory(),
		RuleID:             r.CheckID,
		RuleName:           humanTitle,
	}

	// Fingerprint
	// Note: Semgrep may return "requires login" when pro features are unavailable
	// We validate the fingerprint and generate our own if it's not a valid hash
	if r.Extra.Fingerprint != "" && isValidFingerprint(r.Extra.Fingerprint) {
		finding.Fingerprint = r.Extra.Fingerprint
	} else {
		finding.Fingerprint = core.GenerateSastFingerprint(r.Path, r.CheckID, r.Start.Line)
	}

	// Location
	// Note: Semgrep may return "requires login" for Lines when pro features are unavailable
	// In that case, we read the snippet directly from the source file
	// We ALWAYS read context snippet for better understanding (±3 lines around the vulnerability)
	snippet := r.Extra.Lines
	var contextSnippet string
	var contextStartLine int

	// Always try to read context snippet from source file
	snippetData := readSnippetWithContext(r.Path, r.Start.Line, r.End.Line, DefaultContextLines, opts)
	contextSnippet = snippetData.ContextSnippet
	contextStartLine = snippetData.ContextStartLine

	// If Semgrep didn't return a valid snippet, use the one we read from file
	if snippet == "requires login" || snippet == "" {
		snippet = snippetData.Snippet
	}

	finding.Location = &ctis.FindingLocation{
		Path:             r.Path,
		StartLine:        r.Start.Line,
		EndLine:          r.End.Line,
		StartColumn:      r.Start.Col,
		EndColumn:        r.End.Col,
		Snippet:          snippet,
		ContextSnippet:   contextSnippet,
		ContextStartLine: contextStartLine,
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

	// Vulnerability details (CWE, OWASP, ASVS, etc.)
	cwes := r.GetCWEs()
	owasps := r.GetOWASPs()
	hasASVS := r.Extra.Metadata.Asvs.Section != "" || r.Extra.Metadata.Asvs.Control != ""
	if len(cwes) > 0 || len(owasps) > 0 || hasASVS {
		finding.Vulnerability = &ctis.VulnerabilityDetails{
			CWEIDs:   cwes,
			OWASPIDs: owasps,
		}
		if len(cwes) > 0 {
			finding.Vulnerability.CWEID = cwes[0]
		}
		// Add ASVS compliance info if available
		if hasASVS {
			finding.Vulnerability.ASVS = &ctis.ASVSInfo{
				Section:    r.Extra.Metadata.Asvs.Section,
				ControlID:  r.Extra.Metadata.Asvs.Control,
				ControlURL: r.Extra.Metadata.Asvs.Version,
			}
		}
	}

	// Data flow trace
	if r.Extra.DataflowTrace != nil {
		finding.DataFlow = p.convertDataFlow(r.Extra.DataflowTrace)
	}

	// References
	finding.References = r.GetReferences()

	// Tags
	finding.Tags = []string{
		"sast",
		r.GetCategory(),
	}
	if len(r.Extra.Metadata.Technology) > 0 {
		finding.Tags = append(finding.Tags, r.Extra.Metadata.Technology...)
	}

	// Remediation - separate fields for different purposes:
	// - Recommendation: human-readable guidance text (from message, contains "Ensure that...")
	// - FixCode: actual code to apply (from extra.fix)
	// - FixRegex: regex-based fix pattern
	finding.Remediation = &ctis.Remediation{
		Recommendation: r.Extra.Message, // Message contains both description AND recommendation text
		FixAvailable:   r.Extra.Fix != "" || r.Extra.FixRegex != nil,
		AutoFixable:    r.Extra.Fix != "" || r.Extra.FixRegex != nil,
	}

	// Set fix code separately (actual code to apply)
	if r.Extra.Fix != "" {
		finding.Remediation.FixCode = r.Extra.Fix
	}

	// Add regex-based fix if available
	if r.Extra.FixRegex != nil {
		finding.Remediation.FixRegex = &ctis.FixRegex{
			Regex:       r.Extra.FixRegex.Regex,
			Replacement: r.Extra.FixRegex.Replacement,
			Count:       r.Extra.FixRegex.Count,
		}
	}

	return finding
}

// convertDataFlow converts semgrep dataflow trace to CTIS DataFlow.
func (p *Parser) convertDataFlow(df *DataFlow) *ctis.DataFlow {
	result := &ctis.DataFlow{}

	// Parse taint source
	if source := ConvertCliLoc(df.TaintSource); source != nil {
		result.Sources = append(result.Sources, ctis.DataFlowLocation{
			Path:    source.Location.Path,
			Line:    source.Location.Start.Line,
			Column:  source.Location.Start.Col,
			Content: source.Content,
			Label:   "source",
			Index:   0,
		})
	}

	// Parse intermediate vars
	for i, node := range df.IntermediateVars {
		result.Intermediates = append(result.Intermediates, ctis.DataFlowLocation{
			Path:    node.Location.Path,
			Line:    node.Location.Start.Line,
			Column:  node.Location.Start.Col,
			Content: node.Content,
			Label:   "intermediate",
			Index:   i + 1,
		})
	}

	// Parse taint sink
	sinks := ConvertCliCall(df.TaintSink)
	if len(sinks) == 0 {
		if sink := ConvertCliLoc(df.TaintSink); sink != nil {
			sinks = append(sinks, sink)
		}
	}
	for i, sink := range sinks {
		result.Sinks = append(result.Sinks, ctis.DataFlowLocation{
			Path:    sink.Location.Path,
			Line:    sink.Location.Start.Line,
			Column:  sink.Location.Start.Col,
			Content: sink.Content,
			Label:   "sink",
			Index:   len(df.IntermediateVars) + i + 1,
		})
	}

	return result
}

// ParseToCTIS is a convenience function to parse semgrep JSON to CTIS.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	parser := &Parser{}
	return parser.Parse(context.Background(), data, opts)
}

// isValidFingerprint checks if a fingerprint is a valid hash-like string.
// Semgrep may return "requires login" when pro features are unavailable.
func isValidFingerprint(fp string) bool {
	// Fingerprint should be at least 16 chars (e.g., short hash) and alphanumeric
	if len(fp) < 16 {
		return false
	}
	// Check if it looks like a hex hash (alphanumeric, no spaces)
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// SnippetWithContext contains both the exact snippet and surrounding context.
type SnippetWithContext struct {
	Snippet          string // Exact code at vulnerability location
	ContextSnippet   string // Surrounding code for better understanding
	ContextStartLine int    // Line number where context starts
}

// DefaultContextLines is the number of lines to include before/after the snippet.
const DefaultContextLines = 3

// readSnippetWithContext reads the snippet along with surrounding context lines.
// contextLines specifies how many lines before/after to include (0 = no context).
func readSnippetWithContext(filePath string, startLine, endLine, contextLines int, opts *core.ParseOptions) SnippetWithContext {
	result := SnippetWithContext{}

	if startLine <= 0 || endLine <= 0 || endLine < startLine {
		return result
	}

	// Determine the full path to the file
	fullPath := filePath
	if opts != nil && opts.BasePath != "" {
		if !filepath.IsAbs(filePath) {
			fullPath = filepath.Join(opts.BasePath, filePath)
		}
	}

	// Try to open the file
	file, err := os.Open(fullPath)
	if err != nil {
		return result
	}
	defer func() { _ = file.Close() }()

	// Calculate context boundaries
	contextStart := max(1, startLine-contextLines)
	contextEnd := endLine + contextLines

	// Read lines from file
	scanner := bufio.NewScanner(file)
	var snippetLines []string
	var contextLinesList []string
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		lineText := scanner.Text()

		// Collect snippet lines (exact match)
		if lineNum >= startLine && lineNum <= endLine {
			snippetLines = append(snippetLines, lineText)
		}

		// Collect context lines (wider range)
		if contextLines > 0 && lineNum >= contextStart && lineNum <= contextEnd {
			contextLinesList = append(contextLinesList, lineText)
		}

		// Stop reading after context end
		if lineNum > contextEnd && contextLines > 0 {
			break
		}
		if lineNum > endLine && contextLines == 0 {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return result
	}

	// Build snippet string
	if len(snippetLines) > 0 {
		result.Snippet = joinLines(snippetLines)
	}

	// Build context string
	if len(contextLinesList) > 0 {
		result.ContextSnippet = joinLines(contextLinesList)
		result.ContextStartLine = contextStart
	}

	return result
}

// joinLines joins a slice of strings with newlines.
func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}
