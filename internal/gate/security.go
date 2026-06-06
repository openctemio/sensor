// Package gate provides security gate functionality for CI/CD pipelines.
package gate

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Exit codes for security gate.
const (
	ExitCodePass  = 0 // No findings above threshold
	ExitCodeFail  = 1 // Findings above threshold
	ExitCodeError = 2 // Configuration or runtime error
)

// maxRiskBlocks caps how many risk-blocked findings are listed (they always
// surface, even in non-verbose mode, because they are the reason for failure).
const maxRiskBlocks = 10

// SeverityOrder maps severity strings to numeric values for comparison.
var SeverityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// classifySeverity reports whether a finding's severity meets or exceeds the
// threshold, and the bucket name to count it under. Unknown or empty
// severities fail CLOSED: a security gate must never let a finding through
// merely because its severity label is unrecognized (a new scanner label, a
// typo, or a hostile blank value would otherwise bypass the gate silently).
func classifySeverity(severity string, thresholdLevel int) (bucket string, blocks bool) {
	if level, ok := SeverityOrder[severity]; ok {
		return severity, level >= thresholdLevel
	}
	return "unknown", true
}

// riskReason returns a human label if a finding is actively exploited (CISA KEV)
// or has a known exploit, else "". Such findings BLOCK regardless of the
// severity threshold — real-world exploitability matters more than a severity
// label, and this is what sets the gate apart from a plain severity cutoff.
func riskReason(f ctis.Finding) string {
	if f.Vulnerability == nil {
		return ""
	}
	switch {
	case f.Vulnerability.InCISAKEV:
		return "CISA KEV (actively exploited)"
	case f.Vulnerability.ExploitAvailable:
		return "known exploit available"
	default:
		return ""
	}
}

// Result contains the result of a security gate check.
type Result struct {
	Passed    bool
	Total     int // findings blocked by the severity threshold
	Counts    map[string]int
	Threshold string
	TopBlocks []string
	// RiskBlocks lists findings that are BELOW the severity threshold but block
	// anyway because they are actively exploited / have a known exploit.
	RiskBlocks []string
	RiskCount  int
}

// Check evaluates reports against a severity threshold.
func Check(reports []*ctis.Report, threshold string, maxBlocked int) (*Result, error) {
	return CheckWithSuppressions(reports, threshold, maxBlocked, nil)
}

// CheckWithSuppressions evaluates reports against a severity threshold (plus the
// risk-override for actively-exploited findings), filtering out findings that
// match suppression rules from the platform. A suppressed finding never blocks,
// even if it is KEV — suppression is an explicit, audited operator decision.
func CheckWithSuppressions(reports []*ctis.Report, threshold string, maxBlocked int, suppressions []client.SuppressionRule) (*Result, error) {
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	thresholdLevel, ok := SeverityOrder[threshold]
	if !ok {
		return nil, fmt.Errorf("invalid severity threshold '%s'. Use: critical, high, medium, low", threshold)
	}

	result := &Result{
		Counts:    make(map[string]int),
		Threshold: threshold,
	}

	suppressed := 0

	for _, report := range reports {
		toolName := ""
		if report.Tool != nil {
			toolName = report.Tool.Name
		}

		for _, finding := range report.Findings {
			if isSuppressed(finding, toolName, suppressions) {
				suppressed++
				continue
			}

			severity := strings.ToLower(string(finding.Severity))
			bucket, blocks := classifySeverity(severity, thresholdLevel)
			if blocks {
				result.Counts[bucket]++
				if len(result.TopBlocks) < maxBlocked {
					result.TopBlocks = append(result.TopBlocks, fmt.Sprintf("  - [%s] %s", strings.ToUpper(bucket), finding.Title))
				}
				continue
			}

			// Below the severity threshold — but actively-exploited findings
			// still block (risk-override).
			if reason := riskReason(finding); reason != "" {
				result.RiskCount++
				if len(result.RiskBlocks) < maxRiskBlocks {
					result.RiskBlocks = append(result.RiskBlocks,
						fmt.Sprintf("  - [%s] %s (%s)", strings.ToUpper(severity), finding.Title, reason))
				}
			}
		}
	}

	for _, c := range result.Counts {
		result.Total += c
	}

	result.Passed = result.Total == 0 && result.RiskCount == 0

	if suppressed > 0 && len(result.TopBlocks) < maxBlocked {
		result.TopBlocks = append(result.TopBlocks, fmt.Sprintf("  (Suppressed: %d findings)", suppressed))
	}

	return result, nil
}

// ValidateThreshold checks if a threshold string is valid.
func ValidateThreshold(threshold string) bool {
	_, ok := SeverityOrder[strings.ToLower(strings.TrimSpace(threshold))]
	return ok
}

// CheckAndPrint runs the security gate check and prints results.
// Returns exit code: 0 = pass, 1 = fail, 2 = error.
func CheckAndPrint(reports []*ctis.Report, threshold string, verbose bool) int {
	return CheckAndPrintTo(os.Stdout, os.Stderr, reports, threshold, verbose)
}

// CheckAndPrintTo runs the security gate check and prints results to specified writers.
func CheckAndPrintTo(stdout, stderr io.Writer, reports []*ctis.Report, threshold string, verbose bool) int {
	return CheckAndPrintWithSuppressionsTo(stdout, stderr, reports, threshold, verbose, nil)
}

// CheckAndPrintWithSuppressions runs the security gate check with suppression support.
func CheckAndPrintWithSuppressions(reports []*ctis.Report, threshold string, verbose bool, suppressions []client.SuppressionRule) int {
	return CheckAndPrintWithSuppressionsTo(os.Stdout, os.Stderr, reports, threshold, verbose, suppressions)
}

// CheckAndPrintWithSuppressionsTo runs the security gate check with suppression support to specified writers.
func CheckAndPrintWithSuppressionsTo(stdout, stderr io.Writer, reports []*ctis.Report, threshold string, verbose bool, suppressions []client.SuppressionRule) int {
	maxBlocked := 0
	if verbose {
		maxBlocked = 5
	}

	result, err := CheckWithSuppressions(reports, threshold, maxBlocked, suppressions)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitCodeError
	}
	return printResult(stdout, result, verbose)
}

// printResult renders a Result and returns the exit code. Shared by all the
// CheckAndPrint* entry points so severity + risk reporting never diverge.
func printResult(stdout io.Writer, result *Result, verbose bool) int {
	if result.Passed {
		_, _ = fmt.Fprintf(stdout, "\n✅ Security gate PASSED: no findings >= %s severity (and none actively exploited)\n", result.Threshold)
		return ExitCodePass
	}

	_, _ = fmt.Fprintln(stdout, "\n❌ Security gate FAILED")
	if result.Total > 0 {
		_, _ = fmt.Fprintf(stdout, "   %d finding(s) >= %s severity\n", result.Total, result.Threshold)
		for sev, count := range result.Counts {
			_, _ = fmt.Fprintf(stdout, "     %s: %d\n", strings.ToUpper(sev), count)
		}
		if verbose && len(result.TopBlocks) > 0 {
			_, _ = fmt.Fprintln(stdout, "   Top findings:")
			for _, b := range result.TopBlocks {
				_, _ = fmt.Fprintln(stdout, b)
			}
		}
	}
	if result.RiskCount > 0 {
		_, _ = fmt.Fprintf(stdout, "   %d finding(s) below the threshold but BLOCKED by risk (actively exploited):\n", result.RiskCount)
		for _, b := range result.RiskBlocks {
			_, _ = fmt.Fprintln(stdout, b)
		}
	}
	return ExitCodeFail
}

// isSuppressed checks if a finding matches any suppression rule.
func isSuppressed(f ctis.Finding, reportToolName string, rules []client.SuppressionRule) bool {
	for _, rule := range rules {
		if matchesRule(f, reportToolName, rule) {
			return true
		}
	}
	return false
}

// matchesRule checks if a finding matches a specific suppression rule.
func matchesRule(f ctis.Finding, reportToolName string, rule client.SuppressionRule) bool {
	// Check tool name (from report level)
	if rule.ToolName != "" {
		if !strings.EqualFold(rule.ToolName, reportToolName) {
			return false
		}
	}

	// Check rule ID (supports wildcard suffix)
	if rule.RuleID != "" {
		if strings.HasSuffix(rule.RuleID, "*") {
			prefix := strings.TrimSuffix(rule.RuleID, "*")
			if !strings.HasPrefix(f.RuleID, prefix) {
				return false
			}
		} else if rule.RuleID != f.RuleID {
			return false
		}
	}

	// Check path pattern
	if rule.PathPattern != "" && f.Location != nil && f.Location.Path != "" {
		if !matchGlob(rule.PathPattern, f.Location.Path) {
			return false
		}
	}

	return true
}

// matchGlob provides simple glob matching with ** support.
func matchGlob(pattern, path string) bool {
	// Handle ** patterns
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			if prefix != "" && !strings.HasPrefix(path, prefix) {
				return false
			}
			if suffix != "" && !strings.HasSuffix(path, suffix) {
				return false
			}
			return true
		}
	}

	// Simple wildcard matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	return pattern == path
}
