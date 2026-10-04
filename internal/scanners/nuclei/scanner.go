package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBinary is the default nuclei binary name.
	DefaultBinary = "nuclei"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 60 * time.Minute

	// DefaultRateLimit is the default rate limit (requests per second).
	DefaultRateLimit = 150

	// DefaultConcurrency is the default concurrency level.
	DefaultConcurrency = 25

	// DefaultBulkSize is the default number of hosts scanned in parallel per
	// template (nuclei's own default).
	DefaultBulkSize = 25
)

// Scanner implements the Scanner interface for Nuclei.
type Scanner struct {
	// Configuration
	Binary  string        // Path to nuclei binary (default: "nuclei")
	Timeout time.Duration // Scan timeout (default: 60 minutes)
	Verbose bool          // Enable verbose output

	// Scan options
	Mode        ScanMode // target, list
	TargetFile  string   // File containing list of targets
	Templates   []string // Specific templates to use
	TemplateDir string   // Directory containing templates
	Workflows   []string // Specific workflows to use
	Tags        []string // Filter templates by tags
	ExcludeTags []string // Exclude templates by tags
	Severity    []string // Filter by severity
	Author      []string // Filter by template author
	ExcludeIDs  []string // Template IDs to exclude

	// Rate limiting
	RateLimit           int // Requests per second
	BulkSize            int // Bulk size for parallel processing
	Concurrency         int // Number of concurrent templates
	HeadlessBulkSize    int // Headless bulk size
	HeadlessConcurrency int // Headless concurrency

	// Ceilings set by the sensor's operator (SENSOR_NUCLEI_MAX_*, see
	// LimitsFromEnv); 0 means the Default* value. Every scan runs at or
	// below them: a scan's RateLimit / BulkSize / Concurrency
	// (core.ScanOptions) can lower the scanner's values, never raise them
	// past a ceiling, and the flags are always passed, so nuclei's own
	// defaults never apply unchecked.
	Limits Limits

	// Output options
	OutputFile     string // Output file path (empty = stdout)
	MarkdownExport string // Export results as markdown
	SarifExport    string // Export results as SARIF

	// Interactsh (out-of-band) options. Interactsh is OFF by default: a scan
	// runs with -ni, so no target is made to call out to a third-party host
	// and no scan data leaves through the public oast.* servers. It is on
	// only when one of these opts in, and never when NoInteractsh is set:
	//   - AllowInteractsh, set by the operator for this scanner;
	//   - InteractshServer, the operator's own server (implies opting in);
	//   - core.ScanOptions.AllowInteractsh, set per scan when the platform's
	//     command allows it (an approved intrusive run).
	// Templates that need OAST (tag "oast") are skipped while it is off.
	InteractshServer string // Custom interactsh server (opts in)
	InteractshToken  string // Interactsh auth token (sent only when on)
	NoInteractsh     bool   // Force interactsh off, whatever opts in
	AllowInteractsh  bool   // Opt in to interactsh with the default servers

	// Network options
	Proxy           string   // HTTP/SOCKS proxy
	ProxyAuth       string   // Proxy authentication
	Headers         []string // Custom headers
	FollowRedirects bool     // Follow redirects
	MaxRedirects    int      // Maximum redirects
	DisableCookie   bool     // Disable cookie reuse
	Timeout404      int      // Timeout for 404 detection

	// Headless options
	Headless        bool // Enable headless browser
	HeadlessTimeout int  // Headless browser timeout
	PageTimeout     int  // Page load timeout
	ShowBrowser     bool // Show browser (debug)

	// Misc options
	SystemResolvers     bool // Use system DNS resolvers
	Retries             int  // Number of retries
	LeaveDefaultPorts   bool // Leave default ports in URLs
	StopAtFirstMatch    bool // Stop at first match per host
	NoColor             bool // Disable colored output
	Silent              bool // Silent mode
	AutoUpdateTemplates bool // Update templates before scan

	// DisableUpdateCheck passes -disable-update-check: nuclei neither checks
	// for nor installs template (or engine) updates while it scans. Set it
	// when the templates are managed outside nuclei (TemplateDir), so a scan
	// uses exactly that template set and never downloads another.
	DisableUpdateCheck bool
	// TemplatesVersion is the release of the template set in TemplateDir
	// (the managed content's version). With TemplateDir and
	// DisableUpdateCheck set, each run gets a private nuclei configuration
	// naming that directory and release, with the release's .nuclei-ignore
	// (see NewConfigHome).
	TemplatesVersion string
	// DisableUnsignedTemplates passes -disable-unsigned-templates: nuclei
	// skips every template whose signature is missing or does not match
	// (the official templates are signed by ProjectDiscovery). On by
	// default. The platform's custom templates (ScanOptions.
	// CustomTemplateDir) are not signed by ProjectDiscovery: the SDK
	// verified the platform's own signature on each before writing them, and
	// they run in a separate nuclei run (see Scan), so this check stays on
	// for the sensor's own template set even in a scan with custom
	// templates.
	DisableUnsignedTemplates bool

	// Internal
	version string
}

// NewScanner creates a new Nuclei scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:      DefaultBinary,
		Timeout:     DefaultTimeout,
		Mode:        ScanModeTarget,
		RateLimit:   DefaultRateLimit,
		Concurrency: DefaultConcurrency,
		BulkSize:    DefaultBulkSize,
		Severity:    []string{"critical", "high", "medium", "low"},
		Retries:     1,
		// Only signed templates from the sensor's own set run.
		DisableUnsignedTemplates: true,
		// No update checks or template downloads at scan time: a scan runs
		// the template set the image baked or the sensor's managed content
		// verified and installed, never one nuclei fetched by itself.
		DisableUpdateCheck: true,
	}
}

// NewDAST creates a scanner configured for DAST scanning with safe defaults.
func NewDAST() *Scanner {
	s := NewScanner()
	s.Tags = []string{"cve", "oast", "exposure", "misconfig", "takeover", "default-login", "file"}
	s.ExcludeTags = []string{"dos", "fuzz"}
	return s
}

// NewVulnScanner creates a scanner focused on CVE/vulnerability detection.
func NewVulnScanner() *Scanner {
	s := NewScanner()
	s.Tags = []string{"cve"}
	s.Severity = []string{"critical", "high", "medium"}
	return s
}

// NewMisconfigScanner creates a scanner focused on misconfiguration detection.
func NewMisconfigScanner() *Scanner {
	s := NewScanner()
	s.Tags = []string{"misconfig", "exposure", "config"}
	return s
}

// NewTakeoverScanner creates a scanner focused on subdomain takeover detection.
func NewTakeoverScanner() *Scanner {
	s := NewScanner()
	s.Tags = []string{"takeover"}
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "nuclei"
}

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType {
	return "dast" // DAST scanner type
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	caps := []string{"dast", "vulnerability_scanning"}

	for _, tag := range s.Tags {
		switch tag {
		case "cve":
			caps = append(caps, "cve_detection")
		case "misconfig", "config":
			caps = append(caps, "misconfiguration")
		case "takeover":
			caps = append(caps, "subdomain_takeover")
		case "exposure":
			caps = append(caps, "exposure_detection")
		case "default-login":
			caps = append(caps, "default_credentials")
		case "oast":
			caps = append(caps, "oob_testing")
		}
	}

	return caps
}

// IsInstalled checks if Nuclei is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	installed, version, err := core.VersionOutput(ctx, binary, "-version")
	if err != nil {
		return false, "", err
	}

	if installed {
		s.version = parseVersion(version)
	}

	return installed, s.version, nil
}

// parseVersion extracts the engine version from `nuclei -version` output.
// nuclei prints a colored banner to stderr, e.g.
//
//	[INF] Nuclei Engine Version: v3.11.1
//	[INF] Nuclei Config Directory: /home/openctem/.config/nuclei
//
// (VersionOutput has already removed the colors).
func parseVersion(output string) string {
	if v := core.VersionAfterLabel(output, "Engine Version:"); v != "" {
		return v
	}
	// Older releases: "Current Version: v2.9.x".
	if v := core.VersionAfterLabel(output, "Version:"); v != "" {
		return v
	}
	return strings.TrimSpace(output)
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// Scan implements core.Scanner interface - returns raw JSON Lines output.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	sc, err := s.forScan(opts)
	if err != nil {
		return nil, err
	}
	return sc.execute(ctx, target, "", opts, target)
}

// forScan is the scanner configured with a scan's settings (a copy; the
// scanner itself is not modified).
func (s *Scanner) forScan(opts *core.ScanOptions) (*Scanner, error) {
	if opts == nil {
		return s, nil
	}
	return s.withSettings(opts.Settings)
}

// MaxListTargets bounds how many targets one ScanTargets run takes (the
// platform's per-run limit).
const MaxListTargets = 10000

var _ core.MultiTargetScanner = (*Scanner)(nil)

// ScanTargets scans every target in one nuclei run: the list is written to a
// 0600 temporary file passed with -l and removed afterwards. Targets must
// already be validated by the caller (the command executor runs each through
// its scan-target policy); this rejects entries that would break the one-
// target-per-line file format (newlines, control characters) and bounds the
// count. It does not change the scanner's Mode or TargetFile, so it is safe
// to call concurrently.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no scan targets")
	}
	sc, err := s.forScan(opts)
	if err != nil {
		return nil, err
	}
	if len(targets) > MaxListTargets {
		return nil, fmt.Errorf("too many scan targets: %d (max %d)", len(targets), MaxListTargets)
	}
	for _, t := range targets {
		if strings.TrimSpace(t) == "" {
			return nil, fmt.Errorf("empty scan target in list")
		}
		if strings.HasPrefix(t, "-") {
			return nil, fmt.Errorf("scan target %q looks like a command-line flag", t)
		}
		for _, r := range t {
			if r == '\n' || r == '\r' || unicode.IsControl(r) {
				return nil, fmt.Errorf("scan target %q contains a newline or control character", t)
			}
		}
	}

	f, err := os.CreateTemp("", "nuclei-targets-*.txt") // created 0600
	if err != nil {
		return nil, fmt.Errorf("create target list: %w", err)
	}
	listFile := f.Name()
	defer os.Remove(listFile) //nolint:errcheck // best-effort cleanup
	if _, err := f.WriteString(strings.Join(targets, "\n") + "\n"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write target list: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("write target list: %w", err)
	}

	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	return sc.execute(ctx, "", listFile, opts, fmt.Sprintf("%d targets", len(targets)))
}

// runPass is which templates one nuclei run loads.
type runPass int

const (
	// passOwn runs the sensor's own template set (Templates, TemplateDir,
	// Workflows, or nuclei's default directory), with signatures enforced.
	passOwn runPass = iota
	// passCustom runs only the platform's custom templates
	// (ScanOptions.CustomTemplateDir), signed by the platform and verified
	// by the SDK, with every protocol that runs code or reads local files
	// excluded.
	passCustom
)

// CustomExcludedTypes are the nuclei template types a custom template may
// never use, passed as -exclude-type on the custom-template run: the code
// protocol and javascript run code on the sensor, file reads the sensor's
// disk, headless drives a browser. The platform refuses them at upload and
// CheckCustomTemplates refuses them before the run; this is nuclei's own
// filter on top.
var CustomExcludedTypes = []string{"code", "file", "headless", "javascript"}

// execute runs nuclei for target (or the list file). A scan with custom
// templates is two runs, the sensor's own templates with signatures
// enforced and then the custom templates alone, and its output is both
// runs' output; without own templates configured, only the custom run.
func (s *Scanner) execute(ctx context.Context, target, listFile string, opts *core.ScanOptions, label string) (*core.ScanResult, error) {
	customDir := ""
	if opts != nil {
		customDir = opts.CustomTemplateDir
	}
	if customDir != "" {
		if err := CheckCustomTemplates(customDir); err != nil {
			return nil, err
		}
	}
	env, cleanup, err := s.runEnv()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	roots := s.templateRoots(customDir)

	if customDir == "" {
		return s.run(ctx, s.buildArgsFor(target, listFile, opts, passOwn), env, roots, label)
	}
	var results []*core.ScanResult
	if s.hasOwnTemplates() {
		r, err := s.run(ctx, s.buildArgsFor(target, listFile, opts, passOwn), env, roots, label)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	r, err := s.run(ctx, s.buildArgsFor(target, listFile, opts, passCustom), env, roots, label+" (custom templates)")
	if err != nil {
		return nil, err
	}
	return mergeResults(append(results, r)), nil
}

// managedTemplates reports whether runs use a template set managed outside
// nuclei: a TemplateDir that nuclei neither updates nor replaces.
func (s *Scanner) managedTemplates() bool {
	return s.TemplateDir != "" && s.DisableUpdateCheck && !s.AutoUpdateTemplates
}

// runEnv is the environment of a scan's nuclei runs: for a managed template
// set, a private configuration directory (NewConfigHome) that cleanup
// removes; otherwise nuclei's own configuration (nil).
func (s *Scanner) runEnv() (env map[string]string, cleanup func(), err error) {
	if !s.managedTemplates() {
		return nil, func() {}, nil
	}
	home, err := NewConfigHome(s.TemplateDir, s.TemplatesVersion)
	if err != nil {
		return nil, nil, err
	}
	if s.Verbose {
		fmt.Printf("[nuclei] Templates: %s (release %s, ignore list: %s)\n",
			s.TemplateDir, firstNonEmptyString(s.TemplatesVersion, "unknown"), home.Ignore)
	}
	return home.Env(), func() { _ = home.Close() }, nil
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// hasOwnTemplates reports whether the scanner names its own template set
// (a scan with custom templates then runs both).
func (s *Scanner) hasOwnTemplates() bool {
	return len(s.Templates) > 0 || s.TemplateDir != "" || len(s.Workflows) > 0
}

// mergeResults joins the results of consecutive runs of one scan.
func mergeResults(rs []*core.ScanResult) *core.ScanResult {
	if len(rs) == 1 {
		return rs[0]
	}
	out := *rs[0]
	var raw bytes.Buffer
	var stderr strings.Builder
	for _, r := range rs {
		if len(r.RawOutput) > 0 {
			raw.Write(r.RawOutput)
			if r.RawOutput[len(r.RawOutput)-1] != '\n' {
				raw.WriteByte('\n')
			}
		}
		stderr.WriteString(r.Stderr)
		if r.ExitCode > out.ExitCode {
			out.ExitCode = r.ExitCode
		}
		if r.Error != "" && r != rs[0] {
			if out.Error != "" {
				out.Error += "; "
			}
			out.Error += r.Error
		}
		out.FinishedAt = r.FinishedAt
	}
	out.RawOutput = raw.Bytes()
	out.Stderr = stderr.String()
	out.DurationMs = 0
	for _, r := range rs {
		out.DurationMs += r.DurationMs
	}
	return &out
}

// run executes nuclei with args and env; label describes the target for
// logs. Each result line gets the digest of its template file when that file
// is inside roots (annotateTemplateDigests).
func (s *Scanner) run(ctx context.Context, args []string, env map[string]string, roots []string, label string) (*core.ScanResult, error) {
	start := time.Now()

	if s.Verbose {
		fmt.Printf("[nuclei] Target: %s\n", label)
		fmt.Printf("[nuclei] Tags: %v\n", s.Tags)
		fmt.Printf("[nuclei] Severity: %v\n", s.Severity)
	}

	// Execute nuclei
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		Env:     env,
		Timeout: timeout,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute nuclei: %w", err)
	}

	// Get output
	var outputData []byte
	if s.OutputFile != "" {
		outputData, err = os.ReadFile(s.OutputFile)
		if err != nil && execResult.ExitCode == 0 {
			return nil, fmt.Errorf("failed to read nuclei output: %w", err)
		}
		// Clean up output file
		_ = os.Remove(s.OutputFile)
	} else {
		outputData = execResult.Stdout
	}

	runErr, err := runVerdict(execResult.ExitCode, outputData, string(execResult.Stderr))
	if err != nil {
		return nil, err
	}
	// Hashed now, while the scan still holds its template version.
	outputData = annotateTemplateDigests(outputData, roots)

	result := &core.ScanResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		ExitCode:       execResult.ExitCode,
		RawOutput:      outputData,
		Stderr:         string(execResult.Stderr),
		Error:          runErr,
	}

	if s.Verbose {
		fmt.Printf("[nuclei] Scan completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// ScanDAST performs a DAST scan and returns structured results.
func (s *Scanner) ScanDAST(ctx context.Context, targets []string, opts *core.ScanOptions) (*ScanReport, error) {
	start := time.Now()

	// If multiple targets, write to temp file
	var target string
	if len(targets) == 1 {
		target = targets[0]
	} else {
		tempFile, err := s.writeTargetsFile(targets)
		if err != nil {
			return nil, fmt.Errorf("failed to write targets file: %w", err)
		}
		defer os.Remove(tempFile) //nolint:errcheck // best-effort cleanup
		s.Mode = ScanModeList
		s.TargetFile = tempFile
		target = ""
	}

	// Run scan
	scanResult, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	// Parse JSON Lines output
	results, err := s.parseJSONLines(scanResult.RawOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nuclei output: %w", err)
	}

	report := &ScanReport{
		Results: results,
		Statistics: Statistics{
			StartTime:    time.Unix(scanResult.StartedAt, 0),
			EndTime:      time.Unix(scanResult.FinishedAt, 0),
			Duration:     time.Since(start),
			HostsScanned: len(targets),
			ResultsFound: len(results),
		},
	}

	if s.Verbose {
		fmt.Printf("[nuclei] Found %d results in %dms\n", len(results), scanResult.DurationMs)
	}

	return report, nil
}

// InteractshEnabled reports whether a scan with opts may use Interactsh
// (out-of-band callbacks). False unless AllowInteractsh, InteractshServer or
// opts.AllowInteractsh opts in; always false with NoInteractsh.
func (s *Scanner) InteractshEnabled(opts *core.ScanOptions) bool {
	if s.NoInteractsh {
		return false
	}
	return s.AllowInteractsh || s.InteractshServer != "" || (opts != nil && opts.AllowInteractsh)
}

// buildArgs builds the nuclei command arguments of a run of the sensor's
// own templates (or, with custom templates and no own set, the custom run).
func (s *Scanner) buildArgs(target string, opts *core.ScanOptions) []string {
	pass := passOwn
	if opts != nil && opts.CustomTemplateDir != "" && !s.hasOwnTemplates() {
		pass = passCustom
	}
	return s.buildArgsFor(target, "", opts, pass)
}

// buildArgsFor builds the arguments of one run (pass) for one target, or for
// the target list file listFile when it is set (overriding the scanner's
// Mode).
func (s *Scanner) buildArgsFor(target, listFile string, opts *core.ScanOptions, pass runPass) []string {
	args := []string{}

	// Target specification
	switch {
	case listFile != "":
		args = append(args, "-l", listFile)
	case s.Mode == ScanModeList:
		if s.TargetFile != "" {
			args = append(args, "-l", s.TargetFile)
		}
	case s.Mode == ScanModeResume:
		args = append(args, "-resume")
	default:
		if target != "" {
			args = append(args, "-u", target)
		}
	}

	// Output format - JSON Lines
	args = append(args, "-jsonl")

	// Output file
	if s.OutputFile != "" {
		args = append(args, "-o", s.OutputFile)
	}

	if pass == passCustom {
		// Only the platform's custom templates, never a type that runs
		// code, reads local files or drives a browser.
		args = append(args, "-t", opts.CustomTemplateDir,
			"-exclude-type", strings.Join(CustomExcludedTypes, ","))
	} else {
		// The sensor's own template set.
		for _, t := range s.Templates {
			args = append(args, "-t", t)
		}
		if s.TemplateDir != "" {
			args = append(args, "-t", s.TemplateDir)
		}
		for _, w := range s.Workflows {
			args = append(args, "-w", w)
		}
	}

	// Tag filtering
	if len(s.Tags) > 0 {
		args = append(args, "-tags", strings.Join(s.Tags, ","))
	}
	if len(s.ExcludeTags) > 0 {
		args = append(args, "-etags", strings.Join(s.ExcludeTags, ","))
	}

	// Severity filtering
	if len(s.Severity) > 0 {
		args = append(args, "-severity", strings.Join(s.Severity, ","))
	}

	// Author filtering
	if len(s.Author) > 0 {
		args = append(args, "-author", strings.Join(s.Author, ","))
	}

	// Exclude templates
	if len(s.ExcludeIDs) > 0 {
		for _, id := range s.ExcludeIDs {
			args = append(args, "-exclude-id", id)
		}
	}

	// Rate limiting: always passed, at or below the sensor's ceilings.
	rate, concurrency, bulk := s.EffectiveLimits(opts)
	args = append(args,
		"-rate-limit", strconv.Itoa(rate),
		"-c", strconv.Itoa(concurrency),
		"-bs", strconv.Itoa(bulk))

	// Interactsh: off unless something opts in (see the Scanner fields).
	if s.InteractshEnabled(opts) {
		if s.InteractshServer != "" {
			args = append(args, "-iserver", s.InteractshServer)
		}
		if s.InteractshToken != "" {
			args = append(args, "-itoken", s.InteractshToken)
		}
	} else {
		args = append(args, "-ni")
	}

	// Network options
	if s.Proxy != "" {
		args = append(args, "-proxy", s.Proxy)
	}
	if s.ProxyAuth != "" {
		args = append(args, "-proxy-auth", s.ProxyAuth)
	}
	for _, h := range s.Headers {
		args = append(args, "-header", h)
	}
	if s.FollowRedirects {
		args = append(args, "-follow-redirects")
		if s.MaxRedirects > 0 {
			args = append(args, "-max-redirects", fmt.Sprintf("%d", s.MaxRedirects))
		}
	}

	// Headless options (never for custom templates)
	if s.Headless && pass != passCustom {
		args = append(args, "-headless")
		if s.HeadlessTimeout > 0 {
			args = append(args, "-headless-timeout", fmt.Sprintf("%d", s.HeadlessTimeout))
		}
		if s.PageTimeout > 0 {
			args = append(args, "-page-timeout", fmt.Sprintf("%d", s.PageTimeout))
		}
		if s.ShowBrowser {
			args = append(args, "-show-browser")
		}
		if s.HeadlessConcurrency > 0 {
			args = append(args, "-headc", fmt.Sprintf("%d", s.HeadlessConcurrency))
		}
	}

	// Misc options
	if s.SystemResolvers {
		args = append(args, "-system-resolvers")
	}
	if s.Retries > 1 {
		args = append(args, "-retries", fmt.Sprintf("%d", s.Retries))
	}
	if s.StopAtFirstMatch {
		args = append(args, "-stop-at-first-match")
	}
	if s.NoColor {
		args = append(args, "-nc")
	}
	if s.Silent {
		args = append(args, "-silent")
	}
	if s.AutoUpdateTemplates {
		args = append(args, "-ut")
	}
	if s.DisableUpdateCheck {
		args = append(args, "-disable-update-check")
	}
	if s.DisableUnsignedTemplates && pass != passCustom {
		args = append(args, "-disable-unsigned-templates")
	}

	// Apply options from opts
	if opts != nil {
		for _, exclude := range opts.Exclude {
			args = append(args, "-exclude", exclude)
		}
		args = append(args, opts.ExtraArgs...)
	}

	return args
}

// writeTargetsFile writes targets to a temporary file.
func (s *Scanner) writeTargetsFile(targets []string) (string, error) {
	tempFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return "", err
	}
	defer func() { _ = tempFile.Close() }()

	for _, target := range targets {
		if _, err := tempFile.WriteString(target + "\n"); err != nil {
			return "", err
		}
	}

	return tempFile.Name(), nil
}

// parseJSONLines parses Nuclei's JSON Lines output.
func (s *Scanner) parseJSONLines(data []byte) ([]Result, error) {
	var results []Result

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Increase buffer size for large responses
	const maxCapacity = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var result Result
		if err := json.Unmarshal(line, &result); err != nil {
			if s.Verbose {
				fmt.Printf("[nuclei] Warning: Failed to parse line %d: %v\n", lineNum, err)
			}
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading output: %w", err)
	}

	return results, nil
}

// UpdateTemplates updates Nuclei templates to the latest version.
func (s *Scanner) UpdateTemplates(ctx context.Context) error {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	_, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    []string{"-ut"},
		Timeout: 5 * time.Minute,
		Verbose: s.Verbose,
	})

	return err
}

// ListTemplates lists available templates matching the given criteria.
func (s *Scanner) ListTemplates(ctx context.Context) ([]string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	args := []string{"-tl"}

	if len(s.Tags) > 0 {
		args = append(args, "-tags", strings.Join(s.Tags, ","))
	}
	if len(s.Severity) > 0 {
		args = append(args, "-severity", strings.Join(s.Severity, ","))
	}

	result, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		Timeout: 30 * time.Second,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, err
	}

	var templates []string
	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "[") {
			templates = append(templates, line)
		}
	}

	return templates, scanner.Err()
}

// GetTemplateDir returns the default template directory.
func GetTemplateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "nuclei-templates")
}

// runVerdict decides what a nuclei run's exit status and output mean. The
// sensor never passes -es, so nuclei exits 0 when it ran (with or without
// findings) and non-zero only when it failed.
//
//   - Exit 0 without a fatal log line: a completed run (errMsg empty).
//   - Non-zero exit, or a fatal log line ("[FTL]", e.g. "no templates
//     provided for scan"), with no results: the run did not happen. It is an
//     error, so the command fails instead of reporting a clean scan with 0
//     findings, which a receiver could take as proof that earlier findings
//     are gone.
//   - The same with results: the run stopped part-way. The results are kept
//     and errMsg says why, so the report is marked partial (never full
//     coverage, CTIS spec 4.5) and nothing is auto-resolved from it.
func runVerdict(exitCode int, output []byte, stderr string) (errMsg string, err error) {
	fatal := fatalLine(stderr)
	if exitCode == 0 && fatal == "" {
		return "", nil
	}
	why := fmt.Sprintf("nuclei exited with code %d", exitCode)
	if fatal != "" {
		why += ": " + fatal
	} else if t := lastLine(stderr); t != "" {
		why += ": " + t
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return "", errors.New(why)
	}
	return why + " (results are partial)", nil
}

// fatalLine returns nuclei's first fatal log line ("[FTL] ..."), if any.
func fatalLine(stderr string) string {
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[FTL]") {
			return capLine(l)
		}
	}
	return ""
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return capLine(strings.TrimSpace(lines[len(lines)-1]))
}

// capLine bounds a log line quoted in an error.
func capLine(l string) string {
	const maxLen = 300
	if len(l) > maxLen {
		return l[:maxLen] + "..."
	}
	return l
}
