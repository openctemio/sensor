// Package scanners provides scanner implementations for various security tools.
package scanners

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/recon/subfinder"
	"github.com/openctemio/sensor/internal/scanners/betterleaks"
	"github.com/openctemio/sensor/internal/scanners/codeql"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/scanners/semgrep"
	"github.com/openctemio/sensor/internal/scanners/trivy"
)

// =============================================================================
// Scanner Registry - Plugin system for scanners
// =============================================================================

// Registry manages registered scanners.
type Registry struct {
	secretScanners map[string]core.SecretScanner
	sastScanners   map[string]core.Scanner
	scaScanners    map[string]core.ScaScanner
	reconScanners  map[string]core.ReconScanner
	mu             sync.RWMutex
}

// NewRegistry creates a new scanner registry with built-in scanners.
func NewRegistry() *Registry {
	registry := &Registry{
		secretScanners: make(map[string]core.SecretScanner),
		sastScanners:   make(map[string]core.Scanner),
		scaScanners:    make(map[string]core.ScaScanner),
		reconScanners:  make(map[string]core.ReconScanner),
	}

	// Register built-in scanners
	registry.RegisterSecretScanner(betterleaks.NewScanner())
	registry.RegisterSASTScanner(semgrep.NewScanner())
	// Trivy is registered via preset functions, not as ScaScanner
	// because it implements the general Scanner interface

	// Register built-in recon scanners
	registry.RegisterReconScanner(subfinder.NewScanner())
	registry.RegisterReconScanner(dnsx.NewScanner())
	registry.RegisterReconScanner(naabu.NewScanner())
	registry.RegisterReconScanner(httpx.NewScanner())
	registry.RegisterReconScanner(katana.NewScanner())

	return registry
}

// RegisterSecretScanner adds a secret scanner to the registry.
func (r *Registry) RegisterSecretScanner(scanner core.SecretScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secretScanners[scanner.Name()] = scanner
}

// GetSecretScanner returns a secret scanner by name.
func (r *Registry) GetSecretScanner(name string) core.SecretScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.secretScanners[core.CanonicalScannerName(name)]
}

// ListSecretScanners returns all registered secret scanner names.
func (r *Registry) ListSecretScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.secretScanners))
	for name := range r.secretScanners {
		names = append(names, name)
	}
	return names
}

// RegisterSASTScanner adds a SAST scanner to the registry.
func (r *Registry) RegisterSASTScanner(scanner core.Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sastScanners[scanner.Name()] = scanner
}

// GetSASTScanner returns a SAST scanner by name.
func (r *Registry) GetSASTScanner(name string) core.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sastScanners[name]
}

// ListSASTScanners returns all registered SAST scanner names.
func (r *Registry) ListSASTScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.sastScanners))
	for name := range r.sastScanners {
		names = append(names, name)
	}
	return names
}

// RegisterSCAScanner adds an SCA scanner to the registry.
func (r *Registry) RegisterSCAScanner(scanner core.ScaScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scaScanners[scanner.Name()] = scanner
}

// GetSCAScanner returns an SCA scanner by name.
func (r *Registry) GetSCAScanner(name string) core.ScaScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scaScanners[name]
}

// ListSCAScanners returns all registered SCA scanner names.
func (r *Registry) ListSCAScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.scaScanners))
	for name := range r.scaScanners {
		names = append(names, name)
	}
	return names
}

// RegisterReconScanner adds a recon scanner to the registry.
func (r *Registry) RegisterReconScanner(scanner core.ReconScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reconScanners[scanner.Name()] = scanner
}

// GetReconScanner returns a recon scanner by name.
func (r *Registry) GetReconScanner(name string) core.ReconScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reconScanners[name]
}

// ListReconScanners returns all registered recon scanner names.
func (r *Registry) ListReconScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.reconScanners))
	for name := range r.reconScanners {
		names = append(names, name)
	}
	return names
}

// =============================================================================
// Preset Scanners - Ready-to-use scanner instances
// =============================================================================

// BetterleaksScanner is a type alias for external package access.
type BetterleaksScanner = betterleaks.Scanner

// Betterleaks returns a new betterleaks secret scanner with default configuration.
func Betterleaks() *betterleaks.Scanner {
	return betterleaks.NewScanner()
}

// BetterleaksWithConfig returns a betterleaks scanner with custom configuration.
func BetterleaksWithConfig(opts BetterleaksOptions) *betterleaks.Scanner {
	scanner := betterleaks.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.ConfigFile != "" {
		scanner.ConfigFile = opts.ConfigFile
	}
	if opts.OutputFile != "" {
		scanner.OutputFile = opts.OutputFile
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	scanner.Verbose = opts.Verbose
	return scanner
}

// BetterleaksOptions configures the betterleaks scanner.
type BetterleaksOptions struct {
	Binary     string        // Path to betterleaks binary
	ConfigFile string        // Custom config file (.betterleaks.toml or .gitleaks.toml)
	OutputFile string        // Output file path
	Timeout    time.Duration // Scan timeout
	Verbose    bool          // Enable verbose output
}

// Semgrep returns a new semgrep scanner with default configuration.
func Semgrep() *semgrep.Scanner {
	return semgrep.NewScanner()
}

// SemgrepWithConfig returns a semgrep scanner with custom configuration.
func SemgrepWithConfig(opts SemgrepOptions) *semgrep.Scanner {
	scanner := semgrep.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.OutputFile != "" {
		scanner.OutputFile = opts.OutputFile
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if len(opts.Configs) > 0 {
		scanner.Configs = opts.Configs
	}
	if len(opts.Severities) > 0 {
		scanner.Severities = opts.Severities
	}
	if len(opts.ExcludePaths) > 0 {
		scanner.ExcludePaths = opts.ExcludePaths
	}
	if len(opts.IncludePaths) > 0 {
		scanner.IncludePaths = opts.IncludePaths
	}
	scanner.ProEngine = opts.ProEngine
	scanner.DataflowTrace = opts.DataflowTrace
	if opts.MaxMemory > 0 {
		scanner.MaxMemory = opts.MaxMemory
	}
	if opts.Jobs > 0 {
		scanner.Jobs = opts.Jobs
	}
	scanner.NoGitIgnore = opts.NoGitIgnore
	scanner.Verbose = opts.Verbose
	return scanner
}

// SemgrepOptions configures the semgrep scanner.
type SemgrepOptions struct {
	Binary        string        // Path to semgrep binary
	OutputFile    string        // Output file path
	Timeout       time.Duration // Scan timeout
	Verbose       bool          // Enable verbose output
	Configs       []string      // Config files or registries (default: ["auto"])
	Severities    []string      // Filter by severity: ERROR, WARNING, INFO
	ExcludePaths  []string      // Paths to exclude
	IncludePaths  []string      // Paths to include
	ProEngine     bool          // Use Semgrep Pro engine
	DataflowTrace bool          // Enable dataflow traces (default: true)
	MaxMemory     int           // Max memory in MB (0 = no limit)
	Jobs          int           // Number of parallel jobs (0 = auto)
	NoGitIgnore   bool          // Don't respect .gitignore
}

// =============================================================================
// CodeQL Scanner - Full dataflow analysis
// =============================================================================

// CodeQLScanner is a type alias for external package access.
type CodeQLScanner = codeql.Scanner

// CodeQL returns a new CodeQL scanner with default configuration.
// Note: Language must be set before scanning.
func CodeQL() *codeql.Scanner {
	return codeql.NewScanner()
}

// CodeQLGo returns a CodeQL scanner configured for Go analysis.
func CodeQLGo() *codeql.Scanner {
	return codeql.NewSecurityScanner(codeql.LanguageGo)
}

// CodeQLJava returns a CodeQL scanner configured for Java analysis.
func CodeQLJava() *codeql.Scanner {
	return codeql.NewSecurityScanner(codeql.LanguageJava)
}

// CodeQLJavaScript returns a CodeQL scanner configured for JavaScript/TypeScript analysis.
func CodeQLJavaScript() *codeql.Scanner {
	return codeql.NewSecurityScanner(codeql.LanguageJavaScript)
}

// CodeQLPython returns a CodeQL scanner configured for Python analysis.
func CodeQLPython() *codeql.Scanner {
	return codeql.NewSecurityScanner(codeql.LanguagePython)
}

// CodeQLCPP returns a CodeQL scanner configured for C/C++ analysis.
func CodeQLCPP() *codeql.Scanner {
	return codeql.NewSecurityScanner(codeql.LanguageCPP)
}

// CodeQLWithConfig returns a CodeQL scanner with custom configuration.
func CodeQLWithConfig(opts CodeQLOptions) *codeql.Scanner {
	scanner := codeql.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.OutputFile != "" {
		scanner.OutputFile = opts.OutputFile
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Language != "" {
		scanner.Language = codeql.Language(opts.Language)
	}
	if opts.DatabasePath != "" {
		scanner.DatabasePath = opts.DatabasePath
	}
	if len(opts.QueryPacks) > 0 {
		scanner.QueryPacks = opts.QueryPacks
	}
	if len(opts.QueryFiles) > 0 {
		scanner.QueryFiles = opts.QueryFiles
	}
	if opts.Threads > 0 {
		scanner.Threads = opts.Threads
	}
	if opts.RAMPerThread > 0 {
		scanner.RAMPerThread = opts.RAMPerThread
	}
	scanner.SkipDBCreation = opts.SkipDBCreation
	scanner.Verbose = opts.Verbose
	return scanner
}

// CodeQLOptions configures the CodeQL scanner.
type CodeQLOptions struct {
	Binary         string        // Path to codeql binary
	OutputFile     string        // Output file path
	Timeout        time.Duration // Scan timeout
	Verbose        bool          // Enable verbose output
	Language       string        // Target language: go, java, javascript, python, cpp, csharp, ruby, swift
	DatabasePath   string        // Path to CodeQL database (optional)
	QueryPacks     []string      // Query packs to use (default: security-extended)
	QueryFiles     []string      // Specific .ql files to run
	Threads        int           // Number of threads (0 = auto)
	RAMPerThread   int           // RAM per thread in MB (0 = default)
	SkipDBCreation bool          // Skip database creation (use existing)
}

// TrivyScanner is a type alias for external package access.
type TrivyScanner = trivy.Scanner

// Trivy returns a new trivy scanner with default configuration (filesystem mode).
func Trivy() *trivy.Scanner {
	return trivy.NewScanner()
}

// TrivyFS returns a trivy scanner configured for filesystem scanning.
func TrivyFS() *trivy.Scanner {
	return trivy.NewScanner()
}

// TrivyConfig returns a trivy scanner configured for IaC scanning.
func TrivyConfig() *trivy.Scanner {
	return trivy.NewConfigScanner()
}

// TrivyImage returns a trivy scanner configured for container image scanning.
func TrivyImage() *trivy.Scanner {
	return trivy.NewImageScanner()
}

// TrivyFull returns a trivy scanner that scans for all types (vuln, misconfig, secret).
func TrivyFull() *trivy.Scanner {
	return trivy.NewFullScanner()
}

// TrivyWithConfig returns a trivy scanner with custom configuration.
func TrivyWithConfig(opts TrivyOptions) *trivy.Scanner {
	scanner := trivy.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Mode != "" {
		scanner.Mode = trivy.ScanMode(opts.Mode)
	}
	if len(opts.Scanners) > 0 {
		scanner.Scanners = opts.Scanners
	}
	if len(opts.Severity) > 0 {
		scanner.Severity = opts.Severity
	}
	if len(opts.SkipDirs) > 0 {
		scanner.SkipDirs = opts.SkipDirs
	}
	if len(opts.SkipFiles) > 0 {
		scanner.SkipFiles = opts.SkipFiles
	}
	if opts.CacheDir != "" {
		scanner.CacheDir = opts.CacheDir
	}
	scanner.IgnoreUnfixed = opts.IgnoreUnfixed
	scanner.SkipDBUpdate = opts.SkipDBUpdate
	scanner.OfflineScan = opts.OfflineScan
	scanner.Verbose = opts.Verbose
	return scanner
}

// TrivyOptions configures the trivy scanner.
type TrivyOptions struct {
	Binary        string        // Path to trivy binary
	Timeout       time.Duration // Scan timeout
	Mode          string        // Scan mode: fs, config, image, repo
	Scanners      []string      // Scanners: vuln, misconfig, secret, license
	Severity      []string      // Severity filter: CRITICAL, HIGH, MEDIUM, LOW
	SkipDirs      []string      // Directories to skip
	SkipFiles     []string      // Files to skip
	CacheDir      string        // Trivy cache directory
	IgnoreUnfixed bool          // Ignore unfixed vulnerabilities
	SkipDBUpdate  bool          // Skip vulnerability DB update
	OfflineScan   bool          // Run in offline mode
	Verbose       bool          // Enable verbose output
}

// NucleiScanner is a type alias for external package access.
type NucleiScanner = nuclei.Scanner

// Nuclei returns a new nuclei scanner with default configuration.
func Nuclei() *nuclei.Scanner {
	return nuclei.NewScanner()
}

// NucleiDAST returns a nuclei scanner configured for DAST scanning with safe defaults.
func NucleiDAST() *nuclei.Scanner {
	return nuclei.NewDAST()
}

// NucleiVuln returns a nuclei scanner focused on CVE/vulnerability detection.
func NucleiVuln() *nuclei.Scanner {
	return nuclei.NewVulnScanner()
}

// NucleiMisconfig returns a nuclei scanner focused on misconfiguration detection.
func NucleiMisconfig() *nuclei.Scanner {
	return nuclei.NewMisconfigScanner()
}

// NucleiTakeover returns a nuclei scanner focused on subdomain takeover detection.
func NucleiTakeover() *nuclei.Scanner {
	return nuclei.NewTakeoverScanner()
}

// NucleiWithConfig returns a nuclei scanner with custom configuration.
func NucleiWithConfig(opts NucleiOptions) *nuclei.Scanner {
	scanner := nuclei.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if len(opts.Tags) > 0 {
		scanner.Tags = opts.Tags
	}
	if len(opts.ExcludeTags) > 0 {
		scanner.ExcludeTags = opts.ExcludeTags
	}
	if len(opts.Severity) > 0 {
		scanner.Severity = opts.Severity
	}
	if len(opts.Templates) > 0 {
		scanner.Templates = opts.Templates
	}
	if opts.TemplateDir != "" {
		scanner.TemplateDir = opts.TemplateDir
	}
	if opts.RateLimit > 0 {
		scanner.RateLimit = opts.RateLimit
	}
	if opts.Concurrency > 0 {
		scanner.Concurrency = opts.Concurrency
	}
	if opts.Proxy != "" {
		scanner.Proxy = opts.Proxy
	}
	scanner.Headless = opts.Headless
	scanner.NoInteractsh = opts.NoInteractsh
	scanner.AllowInteractsh = opts.AllowInteractsh
	scanner.FollowRedirects = opts.FollowRedirects
	scanner.Verbose = opts.Verbose
	return scanner
}

// NucleiOptions configures the nuclei scanner.
type NucleiOptions struct {
	Binary          string        // Path to nuclei binary
	Timeout         time.Duration // Scan timeout
	Tags            []string      // Filter templates by tags
	ExcludeTags     []string      // Exclude templates by tags
	Severity        []string      // Filter by severity: critical, high, medium, low, info
	Templates       []string      // Specific templates to use
	TemplateDir     string        // Directory containing templates
	RateLimit       int           // Requests per second
	Concurrency     int           // Number of concurrent templates
	Proxy           string        // HTTP/SOCKS proxy
	Headless        bool          // Enable headless browser
	NoInteractsh    bool          // Force interactsh off
	AllowInteractsh bool          // Opt in to interactsh (off by default)
	FollowRedirects bool          // Follow redirects
	Verbose         bool          // Enable verbose output
}

// =============================================================================
// Scanner Utility Functions
// =============================================================================

// CheckInstalled checks if a scanner is installed and returns version info.
func CheckInstalled(ctx context.Context, scanner interface {
	IsInstalled(context.Context) (bool, string, error)
}) (bool, string, error) {
	return scanner.IsInstalled(ctx)
}

// MustBeInstalled checks if a scanner is installed and panics if not.
func MustBeInstalled(ctx context.Context, scanner interface {
	IsInstalled(context.Context) (bool, string, error)
	Name() string
}) {
	installed, _, err := scanner.IsInstalled(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to check if %s is installed: %v", scanner.Name(), err))
	}
	if !installed {
		panic(fmt.Sprintf("%s is not installed", scanner.Name()))
	}
}

// =============================================================================
// Recon Scanner Presets - Ready-to-use recon scanner instances
// =============================================================================

// SubfinderScanner is a type alias for external package access.
type SubfinderScanner = subfinder.Scanner

// Subfinder returns a new subfinder scanner with default configuration.
func Subfinder() *subfinder.Scanner {
	return subfinder.NewScanner()
}

// SubfinderPassive returns a subfinder scanner configured for passive enumeration.
func SubfinderPassive() *subfinder.Scanner {
	return subfinder.NewPassiveScanner()
}

// SubfinderAggressive returns a subfinder scanner using all sources.
func SubfinderAggressive() *subfinder.Scanner {
	return subfinder.NewAggressiveScanner()
}

// SubfinderWithConfig returns a subfinder scanner with custom configuration.
func SubfinderWithConfig(opts SubfinderOptions) *subfinder.Scanner {
	scanner := subfinder.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Threads > 0 {
		scanner.Threads = opts.Threads
	}
	if len(opts.Sources) > 0 {
		scanner.Sources = opts.Sources
	}
	if len(opts.ExcludeSources) > 0 {
		scanner.ExcludeSources = opts.ExcludeSources
	}
	if len(opts.Resolvers) > 0 {
		scanner.Resolvers = opts.Resolvers
	}
	scanner.All = opts.All
	scanner.Recursive = opts.Recursive
	scanner.Verbose = opts.Verbose
	return scanner
}

// SubfinderOptions configures the subfinder scanner.
type SubfinderOptions struct {
	Binary         string        // Path to subfinder binary
	Timeout        time.Duration // Scan timeout
	Threads        int           // Concurrency level
	Sources        []string      // Sources to use
	ExcludeSources []string      // Sources to exclude
	Resolvers      []string      // Custom DNS resolvers
	All            bool          // Use all sources
	Recursive      bool          // Enable recursive enumeration
	Verbose        bool          // Enable verbose output
}

// DNSXScanner is a type alias for external package access.
type DNSXScanner = dnsx.Scanner

// DNSX returns a new dnsx scanner with default configuration.
func DNSX() *dnsx.Scanner {
	return dnsx.NewScanner()
}

// DNSXARecord returns a dnsx scanner for A/AAAA records only.
func DNSXARecord() *dnsx.Scanner {
	return dnsx.NewARecordScanner()
}

// DNSXFull returns a dnsx scanner for all DNS record types.
func DNSXFull() *dnsx.Scanner {
	return dnsx.NewFullRecordScanner()
}

// DNSXWithConfig returns a dnsx scanner with custom configuration.
func DNSXWithConfig(opts DNSXOptions) *dnsx.Scanner {
	scanner := dnsx.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Threads > 0 {
		scanner.Threads = opts.Threads
	}
	if opts.Retries > 0 {
		scanner.Retries = opts.Retries
	}
	if len(opts.Resolvers) > 0 {
		scanner.Resolvers = opts.Resolvers
	}
	if len(opts.RecordTypes) > 0 {
		scanner.RecordTypes = opts.RecordTypes
	}
	scanner.QueryAll = opts.QueryAll
	scanner.ResponseOnly = opts.ResponseOnly
	scanner.Verbose = opts.Verbose
	return scanner
}

// DNSXOptions configures the dnsx scanner.
type DNSXOptions struct {
	Binary       string        // Path to dnsx binary
	Timeout      time.Duration // Scan timeout
	Threads      int           // Concurrency level
	Retries      int           // Number of retries
	Resolvers    []string      // Custom DNS resolvers
	RecordTypes  []string      // DNS record types to query
	QueryAll     bool          // Query all record types
	ResponseOnly bool          // Output only response values
	Verbose      bool          // Enable verbose output
}

// NaabuScanner is a type alias for external package access.
type NaabuScanner = naabu.Scanner

// Naabu returns a new naabu scanner with default configuration.
func Naabu() *naabu.Scanner {
	return naabu.NewScanner()
}

// NaabuTop100 returns a naabu scanner for top 100 ports.
func NaabuTop100() *naabu.Scanner {
	return naabu.NewTop100Scanner()
}

// NaabuTop1000 returns a naabu scanner for top 1000 ports.
func NaabuTop1000() *naabu.Scanner {
	return naabu.NewTop1000Scanner()
}

// NaabuFull returns a naabu scanner for all 65535 ports.
func NaabuFull() *naabu.Scanner {
	return naabu.NewFullScanner()
}

// NaabuWeb returns a naabu scanner for common web ports.
func NaabuWeb() *naabu.Scanner {
	return naabu.NewWebScanner()
}

// NaabuWithConfig returns a naabu scanner with custom configuration.
func NaabuWithConfig(opts NaabuOptions) *naabu.Scanner {
	scanner := naabu.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Rate > 0 {
		scanner.Rate = opts.Rate
	}
	if opts.Retries > 0 {
		scanner.Retries = opts.Retries
	}
	if opts.Ports != "" {
		scanner.Ports = opts.Ports
	}
	if opts.ScanType != "" {
		scanner.ScanType = naabu.ScanType(opts.ScanType)
	}
	scanner.SkipHostDiscovery = opts.SkipHostDiscovery
	scanner.ServiceVersion = opts.ServiceVersion
	scanner.Verbose = opts.Verbose
	return scanner
}

// NaabuOptions configures the naabu scanner.
type NaabuOptions struct {
	Binary            string        // Path to naabu binary
	Timeout           time.Duration // Scan timeout
	Rate              int           // Packets per second
	Retries           int           // Number of retries
	Ports             string        // Ports to scan
	ScanType          string        // Scan type: s (SYN), c (Connect)
	SkipHostDiscovery bool          // Skip host discovery
	ServiceVersion    bool          // Probe for service versions
	Verbose           bool          // Enable verbose output
}

// HTTPXScanner is a type alias for external package access.
type HTTPXScanner = httpx.Scanner

// HTTPX returns a new httpx scanner with default configuration.
func HTTPX() *httpx.Scanner {
	return httpx.NewScanner()
}

// HTTPXBasic returns a basic httpx prober for availability checks.
func HTTPXBasic() *httpx.Scanner {
	return httpx.NewBasicProber()
}

// HTTPXFull returns a comprehensive httpx prober with all features.
func HTTPXFull() *httpx.Scanner {
	return httpx.NewFullProber()
}

// HTTPXTech returns an httpx scanner focused on technology detection.
func HTTPXTech() *httpx.Scanner {
	return httpx.NewTechDetector()
}

// HTTPXWithConfig returns an httpx scanner with custom configuration.
func HTTPXWithConfig(opts HTTPXOptions) *httpx.Scanner {
	scanner := httpx.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Threads > 0 {
		scanner.Threads = opts.Threads
	}
	if opts.RateLimit > 0 {
		scanner.RateLimit = opts.RateLimit
	}
	scanner.FollowRedirects = opts.FollowRedirects
	if opts.MaxRedirects > 0 {
		scanner.MaxRedirects = opts.MaxRedirects
	}
	scanner.TechDetect = opts.TechDetect
	scanner.StatusCode = opts.StatusCode
	scanner.Title = opts.Title
	scanner.WebServer = opts.WebServer
	scanner.CDN = opts.CDN
	scanner.Verbose = opts.Verbose
	return scanner
}

// HTTPXOptions configures the httpx scanner.
type HTTPXOptions struct {
	Binary          string        // Path to httpx binary
	Timeout         time.Duration // Scan timeout
	Threads         int           // Concurrency level
	RateLimit       int           // Rate limit per second
	FollowRedirects bool          // Follow HTTP redirects
	MaxRedirects    int           // Maximum redirects to follow
	TechDetect      bool          // Technology detection
	StatusCode      bool          // Extract status code
	Title           bool          // Extract page title
	WebServer       bool          // Extract web server
	CDN             bool          // CDN detection
	Verbose         bool          // Enable verbose output
}

// KatanaScanner is a type alias for external package access.
type KatanaScanner = katana.Scanner

// Katana returns a new katana scanner with default configuration.
func Katana() *katana.Scanner {
	return katana.NewScanner()
}

// KatanaBasic returns a basic katana crawler for quick discovery.
func KatanaBasic() *katana.Scanner {
	return katana.NewBasicCrawler()
}

// KatanaDeep returns a comprehensive katana crawler for thorough discovery.
func KatanaDeep() *katana.Scanner {
	return katana.NewDeepCrawler()
}

// KatanaHeadless returns a katana crawler with headless browser support.
func KatanaHeadless() *katana.Scanner {
	return katana.NewHeadlessCrawler()
}

// KatanaWithConfig returns a katana scanner with custom configuration.
func KatanaWithConfig(opts KatanaOptions) *katana.Scanner {
	scanner := katana.NewScanner()
	if opts.Binary != "" {
		scanner.Binary = opts.Binary
	}
	if opts.Timeout > 0 {
		scanner.Timeout = opts.Timeout
	}
	if opts.Concurrency > 0 {
		scanner.Concurrency = opts.Concurrency
	}
	if opts.Depth > 0 {
		scanner.Depth = opts.Depth
	}
	if opts.RateLimit > 0 {
		scanner.RateLimit = opts.RateLimit
	}
	scanner.JSCrawl = opts.JSCrawl
	scanner.FormFill = opts.FormFill
	scanner.Headless = opts.Headless
	if opts.Scope != "" {
		scanner.Scope = katana.ScopeType(opts.Scope)
	}
	scanner.Verbose = opts.Verbose
	return scanner
}

// KatanaOptions configures the katana scanner.
type KatanaOptions struct {
	Binary      string        // Path to katana binary
	Timeout     time.Duration // Scan timeout
	Concurrency int           // Concurrency level
	Depth       int           // Maximum crawl depth
	RateLimit   int           // Rate limit per second
	JSCrawl     bool          // Enable JavaScript crawling
	FormFill    bool          // Enable form filling
	Headless    bool          // Enable headless browser
	Scope       string        // Scope constraint: dn, rdn, fqdn
	Verbose     bool          // Enable verbose output
}
