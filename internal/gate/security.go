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

// SeverityOrder maps severity strings to numeric values for comparison.
var SeverityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// Result contains the result of a security gate check.
type Result struct {
	Passed    bool
	Total     int
	Counts    map[string]int
	Threshold string
	TopBlocks []string
}

// Check evaluates reports against a severity threshold.
// Returns a Result with details about the check.
func Check(reports []*ctis.Report, threshold string, maxBlocked int) (*Result, error) {
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	thresholdLevel, ok := SeverityOrder[threshold]
	if !ok {
		return nil, fmt.Errorf("invalid severity threshold '%s'. Use: critical, high, medium, low", threshold)
	}

	result := &Result{
		Counts:    make(map[string]int),
		Threshold: threshold,
	}

	for _, report := range reports {
		for _, finding := range report.Findings {
			severity := strings.ToLower(string(finding.Severity))
			if level, ok := SeverityOrder[severity]; ok && level >= thresholdLevel {
				result.Counts[severity]++
				if len(result.TopBlocks) < maxBlocked {
					result.TopBlocks = append(result.TopBlocks, fmt.Sprintf("  - [%s] %s", strings.ToUpper(severity), finding.Title))
				}
			}
		}
	}

	for _, c := range result.Counts {
		result.Total += c
	}

	result.Passed = result.Total == 0

	return result, nil
}

// CheckAndPrint runs the security gate check and prints results.
// Returns exit code: 0 = pass, 1 = fail, 2 = error.
func CheckAndPrint(reports []*ctis.Report, threshold string, verbose bool) int {
	return CheckAndPrintTo(os.Stdout, os.Stderr, reports, threshold, verbose)
}

// CheckAndPrintTo runs the security gate check and prints results to specified writers.
func CheckAndPrintTo(stdout, stderr io.Writer, reports []*ctis.Report, threshold string, verbose bool) int {
	maxBlocked := 0
	if verbose {
		maxBlocked = 5
	}

	result, err := Check(reports, threshold, maxBlocked)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitCodeError
	}

	if !result.Passed {
		fmt.Fprintf(stdout, "\n❌ Security gate FAILED: %d finding(s) >= %s severity\n", result.Total, result.Threshold)
		for sev, count := range result.Counts {
			fmt.Fprintf(stdout, "   %s: %d\n", strings.ToUpper(sev), count)
		}
		if verbose && len(result.TopBlocks) > 0 {
			fmt.Fprintln(stdout, "\nTop findings:")
			for _, b := range result.TopBlocks {
				fmt.Fprintln(stdout, b)
			}
		}
		return ExitCodeFail
	}

	fmt.Fprintf(stdout, "\n✅ Security gate PASSED: no findings >= %s severity\n", result.Threshold)
	return ExitCodePass
}

// ValidateThreshold checks if a threshold string is valid.
func ValidateThreshold(threshold string) bool {
	_, ok := SeverityOrder[strings.ToLower(strings.TrimSpace(threshold))]
	return ok
}

// CheckWithSuppressions evaluates reports against a severity threshold,
// filtering out findings that match suppression rules from the platform.
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
		// Get tool name from report
		toolName := ""
		if report.Tool != nil {
			toolName = report.Tool.Name
		}

		for _, finding := range report.Findings {
			// Check if finding is suppressed
			if isSuppressed(finding, toolName, suppressions) {
				suppressed++
				continue
			}

			severity := strings.ToLower(string(finding.Severity))
			if level, ok := SeverityOrder[severity]; ok && level >= thresholdLevel {
				result.Counts[severity]++
				if len(result.TopBlocks) < maxBlocked {
					result.TopBlocks = append(result.TopBlocks, fmt.Sprintf("  - [%s] %s", strings.ToUpper(severity), finding.Title))
				}
			}
		}
	}

	for _, c := range result.Counts {
		result.Total += c
	}

	result.Passed = result.Total == 0

	// Add suppression info to top blocks if any
	if suppressed > 0 && len(result.TopBlocks) < maxBlocked {
		result.TopBlocks = append(result.TopBlocks, fmt.Sprintf("  (Suppressed: %d findings)", suppressed))
	}

	return result, nil
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
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitCodeError
	}

	if !result.Passed {
		fmt.Fprintf(stdout, "\n❌ Security gate FAILED: %d finding(s) >= %s severity\n", result.Total, result.Threshold)
		for sev, count := range result.Counts {
			fmt.Fprintf(stdout, "   %s: %d\n", strings.ToUpper(sev), count)
		}
		if verbose && len(result.TopBlocks) > 0 {
			fmt.Fprintln(stdout, "\nTop findings:")
			for _, b := range result.TopBlocks {
				fmt.Fprintln(stdout, b)
			}
		}
		return ExitCodeFail
	}

	fmt.Fprintf(stdout, "\n✅ Security gate PASSED: no findings >= %s severity\n", result.Threshold)
	return ExitCodePass
}
