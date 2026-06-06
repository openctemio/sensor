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

// TestCheck_UnknownSeverityFailsClosed verifies the gate does not silently let
// findings through when their severity label is unrecognized. A new scanner
// label, a typo, or a blank value must be counted as blocking.
func TestCheck_UnknownSeverityFailsClosed(t *testing.T) {
	reports := []*ctis.Report{
		{
			Tool: &ctis.Tool{Name: "custom"},
			Findings: []ctis.Finding{
				{Title: "weird label", Severity: ctis.Severity("moderate")},
				{Title: "blank label", Severity: ctis.Severity("")},
			},
		},
	}

	result, err := Check(reports, "high", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatalf("gate must FAIL when findings carry unknown severities; got Passed=true")
	}
	if result.Total != 2 {
		t.Fatalf("both unknown-severity findings must be counted; got Total=%d", result.Total)
	}
	if result.Counts["unknown"] != 2 {
		t.Fatalf("unknown severities must bucket under \"unknown\"; got %d", result.Counts["unknown"])
	}
}

// TestCheck_KnownBelowThresholdStillPasses confirms the fail-closed change does
// not over-block: a genuinely low finding below the threshold still passes.
func TestCheck_KnownBelowThresholdStillPasses(t *testing.T) {
	reports := []*ctis.Report{
		{
			Tool:     &ctis.Tool{Name: "semgrep"},
			Findings: []ctis.Finding{{Title: "info note", Severity: ctis.SeverityInfo}},
		},
	}

	result, err := Check(reports, "high", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("info finding below 'high' threshold must pass; got Passed=false (Total=%d)", result.Total)
	}
}

// TestRiskOverride covers the risk-aware gate: a finding BELOW the severity
// threshold still blocks when it is actively exploited (CISA KEV) or has a known
// exploit — and a suppressed finding never blocks even if KEV.
func TestRiskOverride(t *testing.T) {
	lowKEV := ctis.Finding{
		Title: "Outdated lib (KEV)", Severity: ctis.SeverityLow, RuleID: "CVE-2021-1234",
		Vulnerability: &ctis.VulnerabilityDetails{InCISAKEV: true},
	}
	lowExploit := ctis.Finding{
		Title: "Vuln with PoC", Severity: ctis.SeverityLow, RuleID: "CVE-2022-9999",
		Vulnerability: &ctis.VulnerabilityDetails{ExploitAvailable: true},
	}
	plainLow := ctis.Finding{
		Title: "Style nit", Severity: ctis.SeverityLow, RuleID: "style",
	}

	t.Run("KEV below threshold blocks", func(t *testing.T) {
		res, err := Check([]*ctis.Report{{Tool: &ctis.Tool{Name: "trivy"}, Findings: []ctis.Finding{lowKEV}}}, "high", 5)
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed {
			t.Fatal("a CISA-KEV finding below threshold must block")
		}
		if res.Total != 0 || res.RiskCount != 1 {
			t.Fatalf("expected severity Total=0, RiskCount=1; got Total=%d RiskCount=%d", res.Total, res.RiskCount)
		}
	})

	t.Run("exploit-available below threshold blocks", func(t *testing.T) {
		res, _ := Check([]*ctis.Report{{Tool: &ctis.Tool{Name: "trivy"}, Findings: []ctis.Finding{lowExploit}}}, "high", 5)
		if res.Passed || res.RiskCount != 1 {
			t.Fatalf("exploit-available below threshold must block; Passed=%v RiskCount=%d", res.Passed, res.RiskCount)
		}
	})

	t.Run("plain low finding still passes", func(t *testing.T) {
		res, _ := Check([]*ctis.Report{{Tool: &ctis.Tool{Name: "semgrep"}, Findings: []ctis.Finding{plainLow}}}, "high", 5)
		if !res.Passed {
			t.Fatalf("a plain low finding below threshold must pass; RiskCount=%d", res.RiskCount)
		}
	})

	t.Run("suppressed KEV does not block", func(t *testing.T) {
		res, _ := CheckWithSuppressions(
			[]*ctis.Report{{Tool: &ctis.Tool{Name: "trivy"}, Findings: []ctis.Finding{lowKEV}}},
			"high", 5,
			[]client.SuppressionRule{{RuleID: "CVE-2021-1234"}},
		)
		if !res.Passed {
			t.Fatalf("a suppressed KEV finding must not block; RiskCount=%d", res.RiskCount)
		}
	})

	t.Run("KEV at/above threshold counts as severity block not risk", func(t *testing.T) {
		highKEV := ctis.Finding{Title: "RCE", Severity: ctis.SeverityCritical, RuleID: "CVE-2020-0001",
			Vulnerability: &ctis.VulnerabilityDetails{InCISAKEV: true}}
		res, _ := Check([]*ctis.Report{{Tool: &ctis.Tool{Name: "trivy"}, Findings: []ctis.Finding{highKEV}}}, "high", 5)
		if res.Passed || res.Total != 1 || res.RiskCount != 0 {
			t.Fatalf("a critical KEV must block via severity (Total=1, RiskCount=0); got Total=%d RiskCount=%d", res.Total, res.RiskCount)
		}
	})
}
