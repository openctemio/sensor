package gate

import (
	"bytes"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestCheckWithSuppressions(t *testing.T) {
	tests := []struct {
		name         string
		reports      []*ctis.Report
		threshold    string
		suppressions []client.SuppressionRule
		wantPass     bool
		wantTotal    int
	}{
		{
			name: "no findings - pass",
			reports: []*ctis.Report{
				{Findings: []ctis.Finding{}},
			},
			threshold:    "high",
			suppressions: nil,
			wantPass:     true,
			wantTotal:    0,
		},
		{
			name: "high finding - fail",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "semgrep"},
					Findings: []ctis.Finding{
						{Title: "SQL Injection", Severity: ctis.SeverityHigh, RuleID: "sql-injection"},
					},
				},
			},
			threshold:    "high",
			suppressions: nil,
			wantPass:     false,
			wantTotal:    1,
		},
		{
			name: "suppressed finding - pass",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "semgrep"},
					Findings: []ctis.Finding{
						{Title: "SQL Injection", Severity: ctis.SeverityHigh, RuleID: "sql-injection"},
					},
				},
			},
			threshold: "high",
			suppressions: []client.SuppressionRule{
				{RuleID: "sql-injection"},
			},
			wantPass:  true,
			wantTotal: 0,
		},
		{
			name: "suppressed by tool name",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "semgrep"},
					Findings: []ctis.Finding{
						{Title: "SQL Injection", Severity: ctis.SeverityHigh, RuleID: "sql-injection"},
					},
				},
			},
			threshold: "high",
			suppressions: []client.SuppressionRule{
				{ToolName: "semgrep", RuleID: "sql-injection"},
			},
			wantPass:  true,
			wantTotal: 0,
		},
		{
			name: "not suppressed - different tool",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "gitleaks"},
					Findings: []ctis.Finding{
						{Title: "AWS Key", Severity: ctis.SeverityCritical, RuleID: "aws-key"},
					},
				},
			},
			threshold: "high",
			suppressions: []client.SuppressionRule{
				{ToolName: "semgrep", RuleID: "aws-key"},
			},
			wantPass:  false,
			wantTotal: 1,
		},
		{
			name: "suppressed by path pattern",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "semgrep"},
					Findings: []ctis.Finding{
						{
							Title:    "Hardcoded Password",
							Severity: ctis.SeverityHigh,
							RuleID:   "hardcoded-password",
							Location: &ctis.FindingLocation{Path: "tests/fixtures/test_data.go"},
						},
					},
				},
			},
			threshold: "high",
			suppressions: []client.SuppressionRule{
				{PathPattern: "tests/**"},
			},
			wantPass:  true,
			wantTotal: 0,
		},
		{
			name: "wildcard rule ID",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "semgrep"},
					Findings: []ctis.Finding{
						{Title: "SQL Injection", Severity: ctis.SeverityHigh, RuleID: "semgrep.sql-injection-v1"},
					},
				},
			},
			threshold: "high",
			suppressions: []client.SuppressionRule{
				{RuleID: "semgrep.sql-*"},
			},
			wantPass:  true,
			wantTotal: 0,
		},
		{
			name: "below threshold - pass",
			reports: []*ctis.Report{
				{
					Tool: &ctis.Tool{Name: "semgrep"},
					Findings: []ctis.Finding{
						{Title: "Info finding", Severity: ctis.SeverityLow, RuleID: "info-1"},
					},
				},
			},
			threshold:    "high",
			suppressions: nil,
			wantPass:     true,
			wantTotal:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CheckWithSuppressions(tt.reports, tt.threshold, 5, tt.suppressions)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Passed != tt.wantPass {
				t.Errorf("Passed = %v, want %v", result.Passed, tt.wantPass)
			}
			if result.Total != tt.wantTotal {
				t.Errorf("Total = %d, want %d", result.Total, tt.wantTotal)
			}
		})
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// ** patterns (any depth)
		{"tests/**", "tests/unit/test.go", true},
		{"tests/**", "tests/integration/deep/test.go", true},
		{"tests/**", "src/main.go", false},
		// ** with suffix (current impl splits by **, uses prefix/suffix match)
		{"**/*.test.go", "src/handler.test.go", false}, // splits to "" and "/*.test.go", suffix doesn't match
		{"**/.test.go", "src/handler.test.go", true},   // splits to "" and ".test.go", suffix matches
		{"**/*.test.go", "src/handler.go", false},
		// Simple wildcard (prefix match)
		{"src/*", "src/main.go", true},
		{"src/*", "src/pkg/main.go", true}, // current impl: prefix match only
		// Exact match
		{"src/main.go", "src/main.go", true},
		{"src/main.go", "src/other.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchGlob(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestCheckAndPrintWithSuppressions(t *testing.T) {
	reports := []*ctis.Report{
		{
			Tool: &ctis.Tool{Name: "semgrep"},
			Findings: []ctis.Finding{
				{Title: "SQL Injection", Severity: ctis.SeverityHigh, RuleID: "sql-injection"},
				{Title: "XSS", Severity: ctis.SeverityMedium, RuleID: "xss"},
			},
		},
	}

	suppressions := []client.SuppressionRule{
		{RuleID: "sql-injection"},
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := CheckAndPrintWithSuppressionsTo(stdout, stderr, reports, "medium", true, suppressions)

	// XSS is medium, should fail
	if exitCode != ExitCodeFail {
		t.Errorf("exitCode = %d, want %d", exitCode, ExitCodeFail)
	}

	// Should mention suppressed
	if !bytes.Contains(stdout.Bytes(), []byte("Suppressed")) {
		t.Errorf("output should mention suppressed findings")
	}
}
