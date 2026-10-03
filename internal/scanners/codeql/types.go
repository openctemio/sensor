// Package codeql provides a scanner implementation for GitHub CodeQL.
// CodeQL provides full inter-procedural dataflow analysis and outputs SARIF
// with complete codeFlows for taint tracking.
package codeql

// =============================================================================
// SARIF Types for CodeQL Output
// =============================================================================

// SARIFReport represents a SARIF 2.1.0 report from CodeQL.
type SARIFReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single CodeQL analysis run.
type Run struct {
	Tool      Tool       `json:"tool"`
	Results   []Result   `json:"results"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

// Tool describes the CodeQL tool.
type Tool struct {
	Driver     Driver   `json:"driver"`
	Extensions []Driver `json:"extensions,omitempty"`
}

// Driver describes the CodeQL driver/query pack.
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

// Rule describes a CodeQL query rule.
type Rule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     *Message           `json:"shortDescription,omitempty"`
	FullDescription      *Message           `json:"fullDescription,omitempty"`
	DefaultConfiguration *RuleConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           RuleProperties     `json:"properties,omitempty"`
	Help                 *Message           `json:"help,omitempty"`
}

// RuleConfiguration contains default configuration for a rule.
type RuleConfiguration struct {
	Level   string `json:"level,omitempty"` // error, warning, note
	Enabled bool   `json:"enabled,omitempty"`
}

// RuleProperties contains additional rule metadata.
type RuleProperties struct {
	Tags             []string `json:"tags,omitempty"`
	Kind             string   `json:"kind,omitempty"`              // problem, path-problem
	Precision        string   `json:"precision,omitempty"`         // very-high, high, medium, low
	ProblemSeverity  string   `json:"problem.severity,omitempty"`  // error, warning, recommendation
	SecuritySeverity string   `json:"security-severity,omitempty"` // 0.0-10.0
	CWEIDs           []string `json:"cwe,omitempty"`
}

// Message contains text content.
type Message struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// Result represents a single CodeQL finding.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex,omitempty"`
	Level               string            `json:"level,omitempty"` // error, warning, note
	Kind                string            `json:"kind,omitempty"`  // fail, pass, review
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	RelatedLocations    []Location        `json:"relatedLocations,omitempty"`
	CodeFlows           []CodeFlow        `json:"codeFlows,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

// Location represents a location in source code.
type Location struct {
	ID               int               `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	Message          *Message          `json:"message,omitempty"`
}

// PhysicalLocation specifies a file location.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
}

// ArtifactLocation identifies a file.
type ArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     int    `json:"index,omitempty"`
}

// Region specifies a region within a file.
type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

// Snippet contains the source code text.
type Snippet struct {
	Text string `json:"text,omitempty"`
}

// LogicalLocation represents a logical code location (function, class, etc).
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"` // function, method, class, module
	ParentIndex        int    `json:"parentIndex,omitempty"`
}

// CodeFlow represents a complete data flow path (source → sink).
// This is the key structure for taint tracking in CodeQL.
type CodeFlow struct {
	Message     *Message     `json:"message,omitempty"`
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

// ThreadFlow represents a sequence of code locations in a single thread.
type ThreadFlow struct {
	ID        string               `json:"id,omitempty"`
	Message   *Message             `json:"message,omitempty"`
	Locations []ThreadFlowLocation `json:"locations"`
}

// ThreadFlowLocation represents a single step in the data flow.
type ThreadFlowLocation struct {
	Index          int            `json:"index,omitempty"`
	Location       *Location      `json:"location,omitempty"`
	Kinds          []string       `json:"kinds,omitempty"` // source, sink, sanitizer
	NestingLevel   int            `json:"nestingLevel,omitempty"`
	ExecutionOrder int            `json:"executionOrder,omitempty"`
	Importance     string         `json:"importance,omitempty"` // essential, important, unimportant
	State          map[string]any `json:"state,omitempty"`
}

// Artifact describes a file analyzed.
type Artifact struct {
	Location       *ArtifactLocation `json:"location,omitempty"`
	Length         int               `json:"length,omitempty"`
	MimeType       string            `json:"mimeType,omitempty"`
	Encoding       string            `json:"encoding,omitempty"`
	SourceLanguage string            `json:"sourceLanguage,omitempty"`
}

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
