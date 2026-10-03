package codeql

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// =============================================================================
// Scanner Constructor Tests
// =============================================================================

func TestNewScanner(t *testing.T) {
	s := NewScanner()

	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}
	if s.Binary != DefaultBinary {
		t.Errorf("Binary = %q, want %q", s.Binary, DefaultBinary)
	}
	if s.OutputFile != DefaultOutputFile {
		t.Errorf("OutputFile = %q, want %q", s.OutputFile, DefaultOutputFile)
	}
	if s.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", s.Timeout, DefaultTimeout)
	}
	if len(s.QueryPacks) != 1 || s.QueryPacks[0] != DefaultQuerySuite {
		t.Errorf("QueryPacks = %v, want [%q]", s.QueryPacks, DefaultQuerySuite)
	}
	if s.Format != "sarif-latest" {
		t.Errorf("Format = %q, want %q", s.Format, "sarif-latest")
	}
}

func TestNewSecurityScanner(t *testing.T) {
	s := NewSecurityScanner(LanguageGo)

	if s.Language != LanguageGo {
		t.Errorf("Language = %q, want %q", s.Language, LanguageGo)
	}
	if len(s.QueryPacks) != 1 || s.QueryPacks[0] != "security-extended" {
		t.Errorf("QueryPacks = %v, want [%q]", s.QueryPacks, "security-extended")
	}
}

func TestNewQualityScanner(t *testing.T) {
	s := NewQualityScanner(LanguageJava)

	if s.Language != LanguageJava {
		t.Errorf("Language = %q, want %q", s.Language, LanguageJava)
	}
	if len(s.QueryPacks) != 1 || s.QueryPacks[0] != "security-and-quality" {
		t.Errorf("QueryPacks = %v, want [%q]", s.QueryPacks, "security-and-quality")
	}
}

func TestNewFullScanner(t *testing.T) {
	s := NewFullScanner(LanguagePython)

	if s.Language != LanguagePython {
		t.Errorf("Language = %q, want %q", s.Language, LanguagePython)
	}
}

// =============================================================================
// Scanner Interface Tests
// =============================================================================

func TestScanner_Name(t *testing.T) {
	s := NewScanner()
	if s.Name() != "codeql" {
		t.Errorf("Name() = %q, want %q", s.Name(), "codeql")
	}
}

func TestScanner_Type(t *testing.T) {
	s := NewScanner()
	if s.Type() != core.ScannerTypeSAST {
		t.Errorf("Type() = %q, want %q", s.Type(), core.ScannerTypeSAST)
	}
}

func TestScanner_Version(t *testing.T) {
	s := NewScanner()
	s.version = "2.15.0"
	if s.Version() != "2.15.0" {
		t.Errorf("Version() = %q, want %q", s.Version(), "2.15.0")
	}
}

func TestScanner_Capabilities(t *testing.T) {
	s := NewScanner()
	caps := s.Capabilities()

	expectedCaps := []string{
		"sast",
		"code_analysis",
		"vulnerability_detection",
		"taint_tracking",
		"cross_file_analysis",
		"interprocedural_analysis",
		"dataflow_analysis",
		"security_queries",
		"code_quality",
	}

	if len(caps) != len(expectedCaps) {
		t.Errorf("Capabilities() length = %d, want %d", len(caps), len(expectedCaps))
	}

	for i, cap := range expectedCaps {
		if caps[i] != cap {
			t.Errorf("Capabilities()[%d] = %q, want %q", i, caps[i], cap)
		}
	}
}

func TestScanner_SetVerbose(t *testing.T) {
	s := NewScanner()

	if s.Verbose {
		t.Error("Verbose should be false by default")
	}

	s.SetVerbose(true)
	if !s.Verbose {
		t.Error("Verbose should be true after SetVerbose(true)")
	}

	s.SetVerbose(false)
	if s.Verbose {
		t.Error("Verbose should be false after SetVerbose(false)")
	}
}

// =============================================================================
// Build Args Tests
// =============================================================================

func TestScanner_BuildAnalyzeArgs(t *testing.T) {
	tests := []struct {
		name       string
		scanner    *Scanner
		dbPath     string
		outputFile string
		wantArgs   []string
	}{
		{
			name: "default config",
			scanner: &Scanner{
				Language:   LanguageGo,
				QueryPacks: []string{"security-extended"},
				Format:     "sarif-latest",
			},
			dbPath:     "/tmp/db",
			outputFile: "/tmp/results.sarif",
			wantArgs: []string{
				"database", "analyze",
				"/tmp/db",
				"--format=sarif-latest",
				"--output=/tmp/results.sarif",
				"--sarif-add-query-help",
				"codeql/go-queries:security-extended",
			},
		},
		{
			name: "multiple query packs",
			scanner: &Scanner{
				Language:   LanguageJava,
				QueryPacks: []string{"security-extended", "security-and-quality"},
				Format:     "sarif-latest",
			},
			dbPath:     "/tmp/java-db",
			outputFile: "/tmp/java.sarif",
			wantArgs: []string{
				"database", "analyze",
				"/tmp/java-db",
				"--format=sarif-latest",
				"--output=/tmp/java.sarif",
				"--sarif-add-query-help",
				"codeql/java-queries:security-extended",
				"codeql/java-queries:security-and-quality",
			},
		},
		{
			name: "with threads",
			scanner: &Scanner{
				Language:   LanguagePython,
				QueryPacks: []string{"security-extended"},
				Format:     "sarif-latest",
				Threads:    4,
			},
			dbPath:     "/tmp/py-db",
			outputFile: "/tmp/py.sarif",
			wantArgs: []string{
				"database", "analyze",
				"/tmp/py-db",
				"--format=sarif-latest",
				"--output=/tmp/py.sarif",
				"--sarif-add-query-help",
				"codeql/python-queries:security-extended",
				"--threads=4",
			},
		},
		{
			name: "with RAM",
			scanner: &Scanner{
				Language:     LanguageCPP,
				QueryPacks:   []string{"security-extended"},
				Format:       "sarif-latest",
				Threads:      4,
				RAMPerThread: 2048,
			},
			dbPath:     "/tmp/cpp-db",
			outputFile: "/tmp/cpp.sarif",
			wantArgs: []string{
				"database", "analyze",
				"/tmp/cpp-db",
				"--format=sarif-latest",
				"--output=/tmp/cpp.sarif",
				"--sarif-add-query-help",
				"codeql/cpp-queries:security-extended",
				"--threads=4",
				"--ram=8192",
			},
		},
		{
			name: "with specific query files",
			scanner: &Scanner{
				Language:   LanguageJavaScript,
				QueryPacks: []string{"security-extended"},
				QueryFiles: []string{"./queries/custom.ql", "./queries/extra.ql"},
				Format:     "sarif-latest",
			},
			dbPath:     "/tmp/js-db",
			outputFile: "/tmp/js.sarif",
			wantArgs: []string{
				"database", "analyze",
				"/tmp/js-db",
				"--format=sarif-latest",
				"--output=/tmp/js.sarif",
				"--sarif-add-query-help",
				"codeql/javascript-queries:security-extended",
				"./queries/custom.ql",
				"./queries/extra.ql",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.scanner.buildAnalyzeArgs(tt.dbPath, tt.outputFile)

			if len(args) != len(tt.wantArgs) {
				t.Fatalf("buildAnalyzeArgs() returned %d args, want %d\nGot: %v\nWant: %v",
					len(args), len(tt.wantArgs), args, tt.wantArgs)
			}

			for i, arg := range args {
				if arg != tt.wantArgs[i] {
					t.Errorf("buildAnalyzeArgs()[%d] = %q, want %q", i, arg, tt.wantArgs[i])
				}
			}
		})
	}
}

// =============================================================================
// Configuration Tests
// =============================================================================

func TestScanner_Configuration(t *testing.T) {
	s := NewScanner()

	// Set custom configuration
	s.Binary = "/usr/local/bin/codeql"
	s.OutputFile = "custom-output.sarif"
	s.Timeout = 120 * time.Minute
	s.Language = LanguageRuby
	s.DatabasePath = "/custom/db/path"
	s.QueryPacks = []string{"security-extended", "security-and-quality"}
	s.QueryFiles = []string{"custom.ql"}
	s.Threads = 8
	s.RAMPerThread = 4096
	s.Format = "csv"
	s.SkipDBCreation = true
	s.Verbose = true

	// Verify all fields
	if s.Binary != "/usr/local/bin/codeql" {
		t.Errorf("Binary not set correctly")
	}
	if s.OutputFile != "custom-output.sarif" {
		t.Errorf("OutputFile not set correctly")
	}
	if s.Timeout != 120*time.Minute {
		t.Errorf("Timeout not set correctly")
	}
	if s.Language != LanguageRuby {
		t.Errorf("Language not set correctly")
	}
	if s.DatabasePath != "/custom/db/path" {
		t.Errorf("DatabasePath not set correctly")
	}
	if len(s.QueryPacks) != 2 {
		t.Errorf("QueryPacks length incorrect")
	}
	if len(s.QueryFiles) != 1 {
		t.Errorf("QueryFiles length incorrect")
	}
	if s.Threads != 8 {
		t.Errorf("Threads not set correctly")
	}
	if s.RAMPerThread != 4096 {
		t.Errorf("RAMPerThread not set correctly")
	}
	if s.Format != "csv" {
		t.Errorf("Format not set correctly")
	}
	if !s.SkipDBCreation {
		t.Errorf("SkipDBCreation not set correctly")
	}
	if !s.Verbose {
		t.Errorf("Verbose not set correctly")
	}
}

// =============================================================================
// Default Constants Tests
// =============================================================================

func TestDefaultConstants(t *testing.T) {
	if DefaultBinary != "codeql" {
		t.Errorf("DefaultBinary = %q, want %q", DefaultBinary, "codeql")
	}
	if DefaultOutputFile != "codeql-results.sarif" {
		t.Errorf("DefaultOutputFile = %q, want %q", DefaultOutputFile, "codeql-results.sarif")
	}
	if DefaultTimeout != 60*time.Minute {
		t.Errorf("DefaultTimeout = %v, want %v", DefaultTimeout, 60*time.Minute)
	}
	if DefaultQuerySuite != "security-extended" {
		t.Errorf("DefaultQuerySuite = %q, want %q", DefaultQuerySuite, "security-extended")
	}
}

// =============================================================================
// Language for all scanner presets
// =============================================================================

func TestLanguagePresets(t *testing.T) {
	tests := []struct {
		name     string
		scanner  *Scanner
		wantLang Language
	}{
		{"Go", NewSecurityScanner(LanguageGo), LanguageGo},
		{"Java", NewSecurityScanner(LanguageJava), LanguageJava},
		{"JavaScript", NewSecurityScanner(LanguageJavaScript), LanguageJavaScript},
		{"Python", NewSecurityScanner(LanguagePython), LanguagePython},
		{"C++", NewSecurityScanner(LanguageCPP), LanguageCPP},
		{"C#", NewSecurityScanner(LanguageCSharp), LanguageCSharp},
		{"Ruby", NewSecurityScanner(LanguageRuby), LanguageRuby},
		{"Swift", NewSecurityScanner(LanguageSwift), LanguageSwift},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.scanner.Language != tt.wantLang {
				t.Errorf("Language = %q, want %q", tt.scanner.Language, tt.wantLang)
			}
		})
	}
}

// =============================================================================
// Query Pack Generation Tests
// =============================================================================

func TestQueryPackGeneration(t *testing.T) {
	tests := []struct {
		language Language
		pack     string
		expected string
	}{
		{LanguageGo, "security-extended", "codeql/go-queries:security-extended"},
		{LanguageJava, "security-and-quality", "codeql/java-queries:security-and-quality"},
		{LanguageJavaScript, "security-extended", "codeql/javascript-queries:security-extended"},
		{LanguagePython, "security-extended", "codeql/python-queries:security-extended"},
		{LanguageCPP, "security-extended", "codeql/cpp-queries:security-extended"},
		{LanguageCSharp, "security-extended", "codeql/csharp-queries:security-extended"},
		{LanguageRuby, "security-extended", "codeql/ruby-queries:security-extended"},
		{LanguageSwift, "security-extended", "codeql/swift-queries:security-extended"},
	}

	for _, tt := range tests {
		t.Run(string(tt.language), func(t *testing.T) {
			s := &Scanner{
				Language:   tt.language,
				QueryPacks: []string{tt.pack},
				Format:     "sarif-latest",
			}

			args := s.buildAnalyzeArgs("/db", "/out.sarif")

			// Find the query pack argument
			if !slices.Contains(args, tt.expected) {
				t.Errorf("Expected query pack %q not found in args: %v", tt.expected, args)
			}
		})
	}
}

// =============================================================================
// Interface Implementation Test
// =============================================================================

func TestScanner_ImplementsInterface(t *testing.T) {
	// This test verifies that Scanner implements the core.Scanner interface
	// It's a compile-time check, but we can also verify the methods exist
	var _ interface {
		Name() string
		Type() core.ScannerType
		Version() string
		Capabilities() []string
		SetVerbose(bool)
	} = (*Scanner)(nil)
}
