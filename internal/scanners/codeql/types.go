// Package codeql provides a scanner implementation for GitHub CodeQL.
// CodeQL provides full inter-procedural dataflow analysis and outputs SARIF
// with complete codeFlows for taint tracking. The SARIF is converted by the
// SDK's SARIF parser (the ctis importer), not here.
package codeql

// =============================================================================
// CodeQL Database Types
// =============================================================================

// Database represents a CodeQL database.
type Database struct {
	Path          string `json:"path"`
	Language      string `json:"language"`
	CreatedAt     string `json:"created_at,omitempty"`
	SourceRoot    string `json:"source_root,omitempty"`
	ExtractorName string `json:"extractor_name,omitempty"`
}

// QuerySuite represents a collection of CodeQL queries.
type QuerySuite struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Queries     []string `json:"queries"`
}

// =============================================================================
// Supported Languages
// =============================================================================

// Language represents a CodeQL-supported language.
type Language string

const (
	LanguageGo         Language = "go"
	LanguageJava       Language = "java"
	LanguageJavaScript Language = "javascript"
	LanguagePython     Language = "python"
	LanguageCPP        Language = "cpp"
	LanguageCSharp     Language = "csharp"
	LanguageRuby       Language = "ruby"
	LanguageSwift      Language = "swift"
)

// String returns the string representation of the language.
func (l Language) String() string {
	return string(l)
}

// IsValid checks if the language is supported by CodeQL.
func (l Language) IsValid() bool {
	switch l {
	case LanguageGo, LanguageJava, LanguageJavaScript, LanguagePython,
		LanguageCPP, LanguageCSharp, LanguageRuby, LanguageSwift:
		return true
	default:
		return false
	}
}

// SupportedLanguages returns all CodeQL-supported languages.
func SupportedLanguages() []Language {
	return []Language{
		LanguageGo,
		LanguageJava,
		LanguageJavaScript,
		LanguagePython,
		LanguageCPP,
		LanguageCSharp,
		LanguageRuby,
		LanguageSwift,
	}
}
