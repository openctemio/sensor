package codeql

import (
	"errors"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// =============================================================================
// Test Data - Minimal SARIF samples
// =============================================================================

var minimalSARIF = []byte(`{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "version": "2.15.0",
        "rules": []
      }
    },
    "results": []
  }]
}`)

var sarifWithFinding = []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "version": "2.15.0",
        "rules": [{
          "id": "go/sql-injection",
          "name": "SQL Injection",
          "shortDescription": { "text": "SQL query built from user-controlled sources" },
          "properties": {
            "precision": "high",
            "security-severity": "8.0",
            "cwe": ["CWE-89"]
          }
        }]
      }
    },
    "results": [{
      "ruleId": "go/sql-injection",
      "level": "error",
      "message": { "text": "This query depends on user-provided value" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "handlers/user.go" },
          "region": {
            "startLine": 35,
            "startColumn": 10,
            "endLine": 35,
            "endColumn": 50,
            "snippet": { "text": "db.Query(query)" }
          }
        },
        "logicalLocations": [{
          "name": "CreateUser",
          "fullyQualifiedName": "main.CreateUser",
          "kind": "function"
        }]
      }],
      "partialFingerprints": {
        "primaryLocationLineHash": "abc123"
      }
    }]
  }]
}`)

var sarifWithDataFlow = []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "version": "2.15.0",
        "rules": [{
          "id": "go/sql-injection",
          "name": "SQL Injection",
          "shortDescription": { "text": "SQL query built from user-controlled sources" },
          "properties": {
            "precision": "very-high",
            "security-severity": "9.5",
            "cwe": ["CWE-89"],
            "tags": ["security", "external/cwe/cwe-89"]
          },
          "help": {
            "markdown": "See [OWASP](https://owasp.org/sql-injection) and [CWE-89](https://cwe.mitre.org/data/definitions/89.html)"
          }
        }]
      }
    },
    "results": [{
      "ruleId": "go/sql-injection",
      "level": "error",
      "message": { "text": "SQL injection from user input to database query" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "handlers/user.go" },
          "region": { "startLine": 35 }
        }
      }],
      "codeFlows": [{
        "message": { "text": "Taint tracking flow" },
        "threadFlows": [{
          "locations": [
            {
              "index": 0,
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/user.go" },
                  "region": {
                    "startLine": 25,
                    "startColumn": 5,
                    "snippet": { "text": "username := r.FormValue(\"username\")" }
                  }
                },
                "logicalLocations": [{ "name": "CreateUser", "kind": "function" }],
                "message": { "text": "User input received" }
              },
              "kinds": ["source"]
            },
            {
              "index": 1,
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/user.go" },
                  "region": {
                    "startLine": 30,
                    "snippet": { "text": "query := fmt.Sprintf(\"SELECT * FROM users WHERE name='%s'\", username)" }
                  }
                },
                "logicalLocations": [{ "name": "CreateUser", "kind": "function" }],
                "message": { "text": "String concatenation" }
              }
            },
            {
              "index": 2,
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/user.go" },
                  "region": {
                    "startLine": 35,
                    "snippet": { "text": "db.Query(query)" }
                  }
                },
                "logicalLocations": [{ "name": "CreateUser", "kind": "function" }],
                "message": { "text": "SQL query executed" }
              },
              "kinds": ["sink"]
            }
          ]
        }]
      }]
    }]
  }]
}`)

var sarifWithCrossFileDataFlow = []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "version": "2.15.0",
        "rules": [{
          "id": "go/command-injection",
          "properties": {
            "precision": "high",
            "security-severity": "9.0"
          }
        }]
      }
    },
    "results": [{
      "ruleId": "go/command-injection",
      "level": "error",
      "message": { "text": "Command injection vulnerability" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "services/exec.go" },
          "region": { "startLine": 50 }
        }
      }],
      "codeFlows": [{
        "threadFlows": [{
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/api.go" },
                  "region": { "startLine": 10 }
                },
                "logicalLocations": [{ "name": "HandleRequest" }]
              },
              "kinds": ["source"]
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "utils/validator.go" },
                  "region": { "startLine": 25 }
                },
                "logicalLocations": [{ "name": "ValidateInput" }]
              }
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "services/exec.go" },
                  "region": { "startLine": 50 }
                },
                "logicalLocations": [{ "name": "ExecuteCommand" }]
              },
              "kinds": ["sink"]
            }
          ]
        }]
      }]
    }]
  }]
}`)

var sarifWithSanitizer = []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "version": "2.15.0",
        "rules": []
      }
    },
    "results": [{
      "ruleId": "go/xss",
      "level": "warning",
      "message": { "text": "Potential XSS" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "handlers/render.go" },
          "region": { "startLine": 100 }
        }
      }],
      "codeFlows": [{
        "threadFlows": [{
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/render.go" },
                  "region": { "startLine": 80 }
                },
                "logicalLocations": [{ "name": "RenderPage" }]
              },
              "kinds": ["source"]
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/render.go" },
                  "region": { "startLine": 90 }
                },
                "logicalLocations": [{ "name": "EscapeHTML" }]
              },
              "kinds": ["sanitizer"]
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "handlers/render.go" },
                  "region": { "startLine": 100 }
                },
                "logicalLocations": [{ "name": "RenderPage" }]
              },
              "kinds": ["sink"]
            }
          ]
        }]
      }]
    }]
  }]
}`)

// =============================================================================
// Parser Tests
// =============================================================================

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("NewParser() returned nil")
	}
	if p.rules == nil {
		t.Error("Parser rules map should be initialized")
	}
}

func TestParser_Parse_EmptySARIF(t *testing.T) {
	p := NewParser()
	findings, err := p.Parse(minimalSARIF)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Parse() returned %d findings, want 0", len(findings))
	}
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	p := NewParser()
	_, err := p.Parse([]byte(`{invalid json}`))
	if err == nil {
		t.Error("Parse() should return error for invalid JSON")
	}
}

func TestParser_Parse_SingleFinding(t *testing.T) {
	p := NewParser()
	findings, err := p.Parse(sarifWithFinding)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Parse() returned %d findings, want 1", len(findings))
	}

	f := findings[0]

	// Check basic fields
	if f.RuleID != "go/sql-injection" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "go/sql-injection")
	}
	if f.Title != "SQL query built from user-controlled sources" {
		t.Errorf("Title = %q, want %q", f.Title, "SQL query built from user-controlled sources")
	}
	if f.Description != "This query depends on user-provided value" {
		t.Errorf("Description = %q, want %q", f.Description, "This query depends on user-provided value")
	}

	// Check severity (security-severity 8.0 -> High)
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("Severity = %q, want %q", f.Severity, ctis.SeverityHigh)
	}

	// Check confidence (precision: high -> 80)
	if f.Confidence != 80 {
		t.Errorf("Confidence = %d, want 80", f.Confidence)
	}

	// Check CWE
	if f.Vulnerability == nil {
		t.Fatal("Vulnerability should not be nil")
	}
	if len(f.Vulnerability.CWEIDs) != 1 || f.Vulnerability.CWEIDs[0] != "CWE-89" {
		t.Errorf("CWEIDs = %v, want [CWE-89]", f.Vulnerability.CWEIDs)
	}

	// Check location
	if f.Location == nil {
		t.Fatal("Location should not be nil")
	}
	if f.Location.Path != "handlers/user.go" {
		t.Errorf("Location.Path = %q, want %q", f.Location.Path, "handlers/user.go")
	}
	if f.Location.StartLine != 35 {
		t.Errorf("Location.StartLine = %d, want 35", f.Location.StartLine)
	}
	if f.Location.Snippet != "db.Query(query)" {
		t.Errorf("Location.Snippet = %q, want %q", f.Location.Snippet, "db.Query(query)")
	}

	// Check logical location
	if f.Location.LogicalLocation == nil {
		t.Fatal("LogicalLocation should not be nil")
	}
	if f.Location.LogicalLocation.Name != "CreateUser" {
		t.Errorf("LogicalLocation.Name = %q, want %q", f.Location.LogicalLocation.Name, "CreateUser")
	}

	// Check fingerprints
	if len(f.PartialFingerprints) != 1 {
		t.Errorf("PartialFingerprints length = %d, want 1", len(f.PartialFingerprints))
	}
}

func TestParser_Parse_DataFlow(t *testing.T) {
	p := NewParser()
	findings, err := p.Parse(sarifWithDataFlow)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Parse() returned %d findings, want 1", len(findings))
	}

	f := findings[0]

	// Verify severity from security-severity 9.5 -> Critical
	if f.Severity != ctis.SeverityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, ctis.SeverityCritical)
	}

	// Verify confidence from precision: very-high -> 95
	if f.Confidence != 95 {
		t.Errorf("Confidence = %d, want 95", f.Confidence)
	}

	// Check DataFlow exists
	if f.DataFlow == nil {
		t.Fatal("DataFlow should not be nil")
	}

	df := f.DataFlow

	// Check tainted flag
	if !df.Tainted {
		t.Error("DataFlow.Tainted should be true")
	}

	// Check sources
	if len(df.Sources) != 1 {
		t.Errorf("DataFlow.Sources length = %d, want 1", len(df.Sources))
	} else {
		src := df.Sources[0]
		if src.Path != "handlers/user.go" {
			t.Errorf("Source.Path = %q, want %q", src.Path, "handlers/user.go")
		}
		if src.Line != 25 {
			t.Errorf("Source.Line = %d, want 25", src.Line)
		}
		if src.Type != ctis.DataFlowLocationSource {
			t.Errorf("Source.Type = %q, want %q", src.Type, ctis.DataFlowLocationSource)
		}
		if src.TaintState != "tainted" {
			t.Errorf("Source.TaintState = %q, want %q", src.TaintState, "tainted")
		}
		if src.Function != "CreateUser" {
			t.Errorf("Source.Function = %q, want %q", src.Function, "CreateUser")
		}
	}

	// Check intermediates
	if len(df.Intermediates) != 1 {
		t.Errorf("DataFlow.Intermediates length = %d, want 1", len(df.Intermediates))
	} else {
		inter := df.Intermediates[0]
		if inter.Line != 30 {
			t.Errorf("Intermediate.Line = %d, want 30", inter.Line)
		}
		if inter.Type != ctis.DataFlowLocationPropagator {
			t.Errorf("Intermediate.Type = %q, want %q", inter.Type, ctis.DataFlowLocationPropagator)
		}
	}

	// Check sinks
	if len(df.Sinks) != 1 {
		t.Errorf("DataFlow.Sinks length = %d, want 1", len(df.Sinks))
	} else {
		sink := df.Sinks[0]
		if sink.Line != 35 {
			t.Errorf("Sink.Line = %d, want 35", sink.Line)
		}
		if sink.Type != ctis.DataFlowLocationSink {
			t.Errorf("Sink.Type = %q, want %q", sink.Type, ctis.DataFlowLocationSink)
		}
	}

	// Check interprocedural flag (single function = false)
	if df.Interprocedural {
		t.Error("DataFlow.Interprocedural should be false for single function")
	}

	// Check cross-file flag (single file = false)
	if df.CrossFile {
		t.Error("DataFlow.CrossFile should be false for single file")
	}

	// Check call path
	if len(df.CallPath) != 3 {
		t.Errorf("DataFlow.CallPath length = %d, want 3", len(df.CallPath))
	}

	// Check summary
	if df.Summary == "" {
		t.Error("DataFlow.Summary should not be empty")
	}

	// Check tags
	if len(f.Tags) != 2 {
		t.Errorf("Tags length = %d, want 2", len(f.Tags))
	}

	// Check references extracted from help markdown
	if len(f.References) != 2 {
		t.Errorf("References length = %d, want 2", len(f.References))
	}
}

func TestParser_Parse_CrossFileDataFlow(t *testing.T) {
	p := NewParser()
	findings, err := p.Parse(sarifWithCrossFileDataFlow)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Parse() returned %d findings, want 1", len(findings))
	}

	df := findings[0].DataFlow
	if df == nil {
		t.Fatal("DataFlow should not be nil")
	}

	// Check cross-file flag (3 different files)
	if !df.CrossFile {
		t.Error("DataFlow.CrossFile should be true for 3 files")
	}

	// Check interprocedural flag (3 different functions)
	if !df.Interprocedural {
		t.Error("DataFlow.Interprocedural should be true for 3 functions")
	}

	// Verify sources from different file
	if len(df.Sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(df.Sources))
	}
	if df.Sources[0].Path != "handlers/api.go" {
		t.Errorf("Source path = %q, want %q", df.Sources[0].Path, "handlers/api.go")
	}

	// Verify sink in different file
	if len(df.Sinks) != 1 {
		t.Fatalf("Expected 1 sink, got %d", len(df.Sinks))
	}
	if df.Sinks[0].Path != "services/exec.go" {
		t.Errorf("Sink path = %q, want %q", df.Sinks[0].Path, "services/exec.go")
	}
}

func TestParser_Parse_Sanitizer(t *testing.T) {
	p := NewParser()
	findings, err := p.Parse(sarifWithSanitizer)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Parse() returned %d findings, want 1", len(findings))
	}

	df := findings[0].DataFlow
	if df == nil {
		t.Fatal("DataFlow should not be nil")
	}

	// Check sanitizers
	if len(df.Sanitizers) != 1 {
		t.Errorf("DataFlow.Sanitizers length = %d, want 1", len(df.Sanitizers))
	} else {
		san := df.Sanitizers[0]
		if san.Line != 90 {
			t.Errorf("Sanitizer.Line = %d, want 90", san.Line)
		}
		if san.Function != "EscapeHTML" {
			t.Errorf("Sanitizer.Function = %q, want %q", san.Function, "EscapeHTML")
		}
		if san.Type != ctis.DataFlowLocationSanitizer {
			t.Errorf("Sanitizer.Type = %q, want %q", san.Type, ctis.DataFlowLocationSanitizer)
		}
		if san.TaintState != "sanitized" {
			t.Errorf("Sanitizer.TaintState = %q, want %q", san.TaintState, "sanitized")
		}
	}
}

func TestParser_ParseToReport(t *testing.T) {
	p := NewParser()
	// No repository (no options, no versionControlProvenance, not in CI):
	// the findings have no asset, which is an error.
	if _, err := p.ParseToReport(sarifWithFinding); !errors.Is(err, ctis.ErrNoAssetForFindings) {
		t.Fatalf("ParseToReport() without a repository: err = %v, want ctis.ErrNoAssetForFindings", err)
	}

	report, err := p.ParseToReportWithOptions(sarifWithFinding, &core.ParseOptions{AssetValue: "github.com/example/app"})
	if err != nil {
		t.Fatalf("ParseToReport() error = %v", err)
	}

	if report == nil {
		t.Fatal("ParseToReport() returned nil report")
	}
	if report.Version != "1.0" {
		t.Errorf("Report.Version = %q, want %q", report.Version, "1.0")
	}
	if report.Tool == nil {
		t.Fatal("Report.Tool should not be nil")
	}
	if report.Tool.Name != "codeql" {
		t.Errorf("Report.Tool.Name = %q, want %q", report.Tool.Name, "codeql")
	}
	if report.Tool.Version != "2.15.0" {
		t.Errorf("Report.Tool.Version = %q, want %q", report.Tool.Version, "2.15.0")
	}
	if len(report.Findings) != 1 {
		t.Errorf("Report.Findings length = %d, want 1", len(report.Findings))
	}
}

// =============================================================================
// Severity Conversion Tests
// =============================================================================

func TestParser_ConvertLevel(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name     string
		level    string
		rule     *Rule
		expected ctis.Severity
	}{
		{
			name:     "security-severity 9.5 -> critical",
			level:    "error",
			rule:     &Rule{Properties: RuleProperties{SecuritySeverity: "9.5"}},
			expected: ctis.SeverityCritical,
		},
		{
			name:     "security-severity 8.0 -> high",
			level:    "error",
			rule:     &Rule{Properties: RuleProperties{SecuritySeverity: "8.0"}},
			expected: ctis.SeverityHigh,
		},
		{
			name:     "security-severity 5.5 -> medium",
			level:    "error",
			rule:     &Rule{Properties: RuleProperties{SecuritySeverity: "5.5"}},
			expected: ctis.SeverityMedium,
		},
		{
			name:     "security-severity 2.0 -> low",
			level:    "error",
			rule:     &Rule{Properties: RuleProperties{SecuritySeverity: "2.0"}},
			expected: ctis.SeverityLow,
		},
		{
			name:     "security-severity 0.0 -> info",
			level:    "error",
			rule:     &Rule{Properties: RuleProperties{SecuritySeverity: "0.0"}},
			expected: ctis.SeverityInfo,
		},
		{
			name:     "fallback error -> high",
			level:    "error",
			rule:     nil,
			expected: ctis.SeverityHigh,
		},
		{
			name:     "fallback warning -> medium",
			level:    "warning",
			rule:     nil,
			expected: ctis.SeverityMedium,
		},
		{
			name:     "fallback note -> low",
			level:    "note",
			rule:     nil,
			expected: ctis.SeverityLow,
		},
		{
			name:     "fallback unknown -> info",
			level:    "unknown",
			rule:     nil,
			expected: ctis.SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.convertLevel(tt.level, tt.rule)
			if got != tt.expected {
				t.Errorf("convertLevel(%q, rule) = %q, want %q", tt.level, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Confidence Tests
// =============================================================================

func TestParser_GetConfidence(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name      string
		precision string
		expected  int
	}{
		{"very-high", "very-high", 95},
		{"high", "high", 80},
		{"medium", "medium", 60},
		{"low", "low", 40},
		{"unknown", "unknown", 50},
		{"empty", "", 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &Rule{Properties: RuleProperties{Precision: tt.precision}}
			got := p.getConfidence(rule)
			if got != tt.expected {
				t.Errorf("getConfidence(%q) = %d, want %d", tt.precision, got, tt.expected)
			}
		})
	}

	// Test nil rule
	t.Run("nil rule", func(t *testing.T) {
		got := p.getConfidence(nil)
		if got != 50 {
			t.Errorf("getConfidence(nil) = %d, want 50", got)
		}
	})
}

// =============================================================================
// CWE Normalization Tests
// =============================================================================

func TestParser_NormalizeCWEs(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "already normalized",
			input:    []string{"CWE-89", "CWE-79"},
			expected: []string{"CWE-89", "CWE-79"},
		},
		{
			name:     "lowercase prefix",
			input:    []string{"cwe-89"},
			expected: []string{"CWE-89"},
		},
		{
			name:     "no prefix",
			input:    []string{"89", "79"},
			expected: []string{"CWE-89", "CWE-79"},
		},
		{
			name:     "mixed",
			input:    []string{"CWE-89", "cwe-79", "78"},
			expected: []string{"CWE-89", "CWE-79", "CWE-78"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.normalizeCWEs(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("normalizeCWEs() length = %d, want %d", len(got), len(tt.expected))
			}
			for i, cwe := range got {
				if cwe != tt.expected[i] {
					t.Errorf("normalizeCWEs()[%d] = %q, want %q", i, cwe, tt.expected[i])
				}
			}
		})
	}
}

// =============================================================================
// Title Building Tests
// =============================================================================

func TestParser_BuildTitle(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name     string
		result   *Result
		rule     *Rule
		expected string
	}{
		{
			name:     "from shortDescription",
			result:   &Result{RuleID: "go/sql-injection"},
			rule:     &Rule{ShortDescription: &Message{Text: "SQL Injection vulnerability"}},
			expected: "SQL Injection vulnerability",
		},
		{
			name:     "from rule name",
			result:   &Result{RuleID: "go/sql-injection"},
			rule:     &Rule{Name: "SQL Injection"},
			expected: "SQL Injection",
		},
		{
			name:     "from rule ID with path",
			result:   &Result{RuleID: "go/sql-injection"},
			rule:     nil,
			expected: "Sql Injection",
		},
		{
			name:     "from rule ID without path",
			result:   &Result{RuleID: "sql-injection"},
			rule:     nil,
			expected: "sql-injection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.buildTitle(tt.result, tt.rule)
			if got != tt.expected {
				t.Errorf("buildTitle() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Reference Extraction Tests
// =============================================================================

func TestParser_ExtractReferences(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name     string
		markdown string
		expected []string
	}{
		{
			name:     "single link",
			markdown: "See [OWASP](https://owasp.org) for more info.",
			expected: []string{"https://owasp.org"},
		},
		{
			name:     "multiple links",
			markdown: "[Link1](http://a.com) and [Link2](http://b.com)",
			expected: []string{"http://a.com", "http://b.com"},
		},
		{
			name:     "no links",
			markdown: "No links here",
			expected: nil,
		},
		{
			name:     "empty string",
			markdown: "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.extractReferences(tt.markdown)
			if len(got) != len(tt.expected) {
				t.Fatalf("extractReferences() length = %d, want %d", len(got), len(tt.expected))
			}
			for i, ref := range got {
				if ref != tt.expected[i] {
					t.Errorf("extractReferences()[%d] = %q, want %q", i, ref, tt.expected[i])
				}
			}
		})
	}
}

// =============================================================================
// DataFlow Summary Tests
// =============================================================================

func TestParser_BuildDataFlowSummary(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name     string
		df       *ctis.DataFlow
		contains []string
	}{
		{
			name: "basic flow",
			df: &ctis.DataFlow{
				Sources: []ctis.DataFlowLocation{{Path: "a.go", Line: 10}},
				Sinks:   []ctis.DataFlowLocation{{Path: "b.go", Line: 20, Function: "dangerous"}},
			},
			contains: []string{"flows from", "a.go:10", "dangerous()"},
		},
		{
			name: "with intermediates",
			df: &ctis.DataFlow{
				Sources:       []ctis.DataFlowLocation{{Path: "a.go", Line: 10}},
				Intermediates: []ctis.DataFlowLocation{{}, {}, {}},
				Sinks:         []ctis.DataFlowLocation{{Path: "b.go", Line: 20}},
			},
			contains: []string{"through 3 step(s)"},
		},
		{
			name: "with label",
			df: &ctis.DataFlow{
				Sources: []ctis.DataFlowLocation{{Path: "a.go", Line: 10, Label: "userInput"}},
				Sinks:   []ctis.DataFlowLocation{{Path: "b.go", Line: 20}},
			},
			contains: []string{"userInput flows from"},
		},
		{
			name: "empty sources",
			df: &ctis.DataFlow{
				Sources: []ctis.DataFlowLocation{},
				Sinks:   []ctis.DataFlowLocation{{Path: "b.go", Line: 20}},
			},
			contains: nil, // Should return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.buildDataFlowSummary(tt.df)
			if tt.contains == nil {
				if got != "" {
					t.Errorf("buildDataFlowSummary() = %q, want empty", got)
				}
				return
			}
			for _, substr := range tt.contains {
				if !containsString(got, substr) {
					t.Errorf("buildDataFlowSummary() = %q, should contain %q", got, substr)
				}
			}
		})
	}
}

// =============================================================================
// Convenience Functions Tests
// =============================================================================

func TestParseSARIF(t *testing.T) {
	findings, err := ParseSARIF(sarifWithFinding)
	if err != nil {
		t.Fatalf("ParseSARIF() error = %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("ParseSARIF() returned %d findings, want 1", len(findings))
	}
}

func TestSlugToTitle(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sql-injection", "Sql Injection"},
		{"command_injection", "Command Injection"},
		{"xss", "Xss"},
		{"path-traversal-attack", "Path Traversal Attack"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := slugToTitle(tt.input)
			if got != tt.expected {
				t.Errorf("slugToTitle(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Language Tests
// =============================================================================

func TestLanguage_IsValid(t *testing.T) {
	valid := []Language{
		LanguageGo, LanguageJava, LanguageJavaScript,
		LanguagePython, LanguageCPP, LanguageCSharp,
		LanguageRuby, LanguageSwift,
	}

	for _, lang := range valid {
		if !lang.IsValid() {
			t.Errorf("Language(%q).IsValid() = false, want true", lang)
		}
	}

	invalid := Language("php")
	if invalid.IsValid() {
		t.Errorf("Language(%q).IsValid() = true, want false", invalid)
	}
}

func TestSupportedLanguages(t *testing.T) {
	langs := SupportedLanguages()
	if len(langs) != 8 {
		t.Errorf("SupportedLanguages() length = %d, want 8", len(langs))
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
