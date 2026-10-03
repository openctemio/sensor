package trivy

// ScanMode represents the type of Trivy scan.
type ScanMode string

const (
	// ScanModeFS scans filesystem for vulnerabilities.
	ScanModeFS ScanMode = "fs"
	// ScanModeConfig scans for misconfigurations.
	ScanModeConfig ScanMode = "config"
	// ScanModeImage scans container images.
	ScanModeImage ScanMode = "image"
	// ScanModeRepo scans git repositories.
	ScanModeRepo ScanMode = "repo"
)

// =============================================================================
// Trivy JSON Output Types
// =============================================================================

// Report represents the root Trivy JSON output.
type Report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	CreatedAt     string   `json:"CreatedAt"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Metadata      Metadata `json:"Metadata"`
	Results       []Result `json:"Results"`
}

// Metadata contains scan metadata.
type Metadata struct {
	OS          *OSInfo      `json:"OS,omitempty"`
	ImageID     string       `json:"ImageID,omitempty"`
	DiffIDs     []string     `json:"DiffIDs,omitempty"`
	RepoTags    []string     `json:"RepoTags,omitempty"`
	RepoDigests []string     `json:"RepoDigests,omitempty"`
	ImageConfig *ImageConfig `json:"ImageConfig,omitempty"`
}

// OSInfo contains OS information.
type OSInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
	EOSL   bool   `json:"EOSL,omitempty"`
}

// ImageConfig contains container image configuration.
type ImageConfig struct {
	Architecture string `json:"architecture,omitempty"`
	OS           string `json:"os,omitempty"`
}

// Result represents a single scan result (per target).
type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"` // os-pkgs, lang-pkgs, config, secret
	Type              string             `json:"Type"`  // alpine, debian, go, npm, terraform, etc.
	Vulnerabilities   []Vulnerability    `json:"Vulnerabilities,omitempty"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations,omitempty"`
	Secrets           []Secret           `json:"Secrets,omitempty"`
	Licenses          []License          `json:"Licenses,omitempty"`
	Packages          []Package          `json:"Packages,omitempty"`
}

// Package represents a dependency package.
type Package struct {
	ID       string   `json:"ID"`
	Name     string   `json:"Name"`
	Version  string   `json:"Version"`
	PkgPath  string   `json:"PkgPath,omitempty"`
	Layer    *Layer   `json:"Layer,omitempty"`
	FilePath string   `json:"FilePath,omitempty"`
	Licenses []string `json:"Licenses,omitempty"`

	// Dependencies
	DependsOn []string `json:"DependsOn,omitempty"`

	// Relationship
	Relationship string `json:"Relationship,omitempty"` // root, direct, indirect, unknown
	Indirect     bool   `json:"Indirect,omitempty"`

	// Identifiers
	Identifier PkgIdentifier `json:"Identifier,omitempty"`

	// Locations where this package is defined
	Locations []PkgLocation `json:"Locations,omitempty"`
}

// PkgLocation represents a location in a manifest file.
type PkgLocation struct {
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}

// PkgIdentifier contains package identifiers.
type PkgIdentifier struct {
	PURL string `json:"PURL,omitempty"`
	UID  string `json:"UID,omitempty"`
}

// =============================================================================
// Vulnerability Types
// =============================================================================

// Vulnerability represents a detected vulnerability.
type Vulnerability struct {
	VulnerabilityID  string      `json:"VulnerabilityID"`
	PkgID            string      `json:"PkgID,omitempty"`
	PkgName          string      `json:"PkgName"`
	PkgPath          string      `json:"PkgPath,omitempty"`
	InstalledVersion string      `json:"InstalledVersion"`
	FixedVersion     string      `json:"FixedVersion,omitempty"`
	Layer            *Layer      `json:"Layer,omitempty"`
	SeveritySource   string      `json:"SeveritySource,omitempty"`
	PrimaryURL       string      `json:"PrimaryURL,omitempty"`
	DataSource       *DataSource `json:"DataSource,omitempty"`

	// Vulnerability details
	Title          string         `json:"Title,omitempty"`
	Description    string         `json:"Description,omitempty"`
	Severity       string         `json:"Severity"`
	CweIDs         []string       `json:"CweIDs,omitempty"`
	VendorSeverity map[string]int `json:"VendorSeverity,omitempty"`

	// CVSS scores
	CVSS map[string]CVSSData `json:"CVSS,omitempty"`

	// References
	References []string `json:"References,omitempty"`

	// Dates
	PublishedDate    string `json:"PublishedDate,omitempty"`
	LastModifiedDate string `json:"LastModifiedDate,omitempty"`

	// Status
	Status string `json:"Status,omitempty"` // affected, fixed, under_investigation, etc.
}

// Layer represents the container layer where vulnerability was found.
type Layer struct {
	Digest string `json:"Digest,omitempty"`
	DiffID string `json:"DiffID,omitempty"`
}

// DataSource represents the vulnerability data source.
type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

// CVSSData contains CVSS score information.
type CVSSData struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

// =============================================================================
// Misconfiguration Types
// =============================================================================

// Misconfiguration represents a detected misconfiguration.
type Misconfiguration struct {
	Type        string   `json:"Type"` // Terraform, Dockerfile, Kubernetes, etc.
	ID          string   `json:"ID"`   // AVD-AWS-0001
	AVDID       string   `json:"AVDID,omitempty"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Message     string   `json:"Message"`
	Namespace   string   `json:"Namespace,omitempty"`
	Query       string   `json:"Query,omitempty"`
	Resolution  string   `json:"Resolution,omitempty"`
	Severity    string   `json:"Severity"`
	PrimaryURL  string   `json:"PrimaryURL,omitempty"`
	References  []string `json:"References,omitempty"`
	Status      string   `json:"Status"` // FAIL, PASS
	Layer       *Layer   `json:"Layer,omitempty"`

	// Location in code
	CauseMetadata CauseMetadata `json:"CauseMetadata,omitempty"`
}

// CauseMetadata contains location information for misconfigurations.
type CauseMetadata struct {
	Resource  string `json:"Resource,omitempty"`
	Provider  string `json:"Provider,omitempty"`
	Service   string `json:"Service,omitempty"`
	StartLine int    `json:"StartLine,omitempty"`
	EndLine   int    `json:"EndLine,omitempty"`
	Code      Code   `json:"Code,omitempty"`
}

// Code contains the code snippet.
type Code struct {
	Lines []CodeLine `json:"Lines,omitempty"`
}

// CodeLine represents a line of code.
type CodeLine struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation,omitempty"`
	Truncated   bool   `json:"Truncated,omitempty"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause,omitempty"`
	LastCause   bool   `json:"LastCause,omitempty"`
}

// =============================================================================
// Secret Types
// =============================================================================

// Secret represents a detected secret.
type Secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Code      Code   `json:"Code,omitempty"`
	Match     string `json:"Match"`
	Layer     *Layer `json:"Layer,omitempty"`
}

// =============================================================================
// License Types
// =============================================================================

// License represents a detected license.
type License struct {
	Severity   string  `json:"Severity"`
	Category   string  `json:"Category"`
	PkgName    string  `json:"PkgName"`
	FilePath   string  `json:"FilePath,omitempty"`
	Name       string  `json:"Name"`
	Confidence float64 `json:"Confidence"`
	Link       string  `json:"Link,omitempty"`
}

// =============================================================================
// Helper Types
// =============================================================================

// SeverityMapping maps Trivy severity to CTIS severity.
var SeverityMapping = map[string]string{
	"CRITICAL": "critical",
	"HIGH":     "high",
	"MEDIUM":   "medium",
	"LOW":      "low",
	"UNKNOWN":  "info",
}

// GetCTISSeverity converts Trivy severity to CTIS severity.
func GetCTISSeverity(trivySeverity string) string {
	if s, ok := SeverityMapping[trivySeverity]; ok {
		return s
	}
	return "info"
}

// GetBestCVSSScore extracts the best available CVSS score.
// Priority: NVD v3 > NVD v2 > other sources
func GetBestCVSSScore(cvss map[string]CVSSData) (float64, string, string) {
	// Priority order for CVSS sources
	sources := []string{"nvd", "ghsa", "redhat", "ubuntu", "debian", "amazon"}

	for _, src := range sources {
		if data, ok := cvss[src]; ok {
			if data.V3Score > 0 {
				return data.V3Score, data.V3Vector, src
			}
			if data.V2Score > 0 {
				return data.V2Score, data.V2Vector, src
			}
		}
	}

	// Fallback to any available source
	for src, data := range cvss {
		if data.V3Score > 0 {
			return data.V3Score, data.V3Vector, src
		}
		if data.V2Score > 0 {
			return data.V2Score, data.V2Vector, src
		}
	}

	return 0, "", ""
}

// ClassToFindingType maps Trivy class to CTIS finding type.
func ClassToFindingType(class string) string {
	switch class {
	case "os-pkgs", "lang-pkgs":
		return "vulnerability"
	case "config":
		return "misconfiguration"
	case "secret":
		return "secret"
	default:
		return "vulnerability"
	}
}
