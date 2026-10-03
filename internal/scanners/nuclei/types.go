package nuclei

import "time"

// ScanMode represents the Nuclei scan mode.
type ScanMode string

const (
	ScanModeTarget   ScanMode = "target"   // Single target
	ScanModeList     ScanMode = "list"     // List of targets from file
	ScanModeResume   ScanMode = "resume"   // Resume previous scan
	ScanModeWorkflow ScanMode = "workflow" // Workflow mode
)

// Result represents a single finding from Nuclei's JSON output.
// Based on Nuclei's JSON Lines output format.
type Result struct {
	// Template information
	TemplateID   string       `json:"template-id"`
	TemplatePath string       `json:"template-path,omitempty"`
	Info         TemplateInfo `json:"info"`

	// Target information
	Type    string `json:"type"` // http, dns, file, ssl, etc.
	Host    string `json:"host"`
	Matched string `json:"matched-at,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    string `json:"port,omitempty"`
	URL     string `json:"url,omitempty"`

	// Match details
	ExtractedResults []string `json:"extracted-results,omitempty"`
	Request          string   `json:"request,omitempty"`
	Response         string   `json:"response,omitempty"`
	CurlCommand      string   `json:"curl-command,omitempty"`

	// Interaction data (for OOB testing)
	Interaction *Interaction `json:"interaction,omitempty"`

	// Matcher metadata
	MatcherName   string `json:"matcher-name,omitempty"`
	MatcherStatus bool   `json:"matcher-status,omitempty"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// TemplateInfo contains information about the template that matched.
type TemplateInfo struct {
	// Identity
	Name        string   `json:"name"`
	Author      []string `json:"author,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`

	// Classification
	Severity       string          `json:"severity"` // info, low, medium, high, critical
	Reference      []string        `json:"reference,omitempty"`
	Classification *Classification `json:"classification,omitempty"`

	// Metadata
	Metadata    map[string]any `json:"metadata,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
}

// Classification contains vulnerability classification details.
type Classification struct {
	CVSSMetrics    string   `json:"cvss-metrics,omitempty"`
	CVSSScore      float64  `json:"cvss-score,omitempty"`
	CVEId          []string `json:"cve-id,omitempty"`
	CWEId          []string `json:"cwe-id,omitempty"`
	CPEURI         string   `json:"cpe,omitempty"`
	EPSSScore      float64  `json:"epss-score,omitempty"`
	EPSSPercentile float64  `json:"epss-percentile,omitempty"`
}

// Interaction contains OOB (Out-of-Band) interaction data.
type Interaction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	QType         string    `json:"q-type,omitempty"`
	RawRequest    string    `json:"raw-request,omitempty"`
	RawResponse   string    `json:"raw-response,omitempty"`
	SMTPFrom      string    `json:"smtp-from,omitempty"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

// Statistics contains scan statistics from Nuclei.
type Statistics struct {
	// Template stats
	TemplatesLoaded  int `json:"templates_loaded"`
	TemplatesMatched int `json:"templates_matched"`

	// Request stats
	RequestsTotal     int64 `json:"requests_total"`
	RequestsPerSecond int   `json:"requests_per_second"`

	// Timing
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Result stats
	HostsScanned int `json:"hosts_scanned"`
	ResultsFound int `json:"results_found"`
	ErrorsCount  int `json:"errors_count"`
}

// ScanReport aggregates all results from a Nuclei scan.
type ScanReport struct {
	Results    []Result   `json:"results"`
	Statistics Statistics `json:"statistics"`
}

// Severity mapping for Nuclei
var SeverityMap = map[string]string{
	"critical": "critical",
	"high":     "high",
	"medium":   "medium",
	"low":      "low",
	"info":     "info",
	"unknown":  "info",
}

// GetCTISSeverity converts Nuclei severity to CTIS severity.
func GetCTISSeverity(severity string) string {
	if mapped, ok := SeverityMap[severity]; ok {
		return mapped
	}
	return "medium"
}
