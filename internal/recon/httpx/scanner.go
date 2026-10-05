// Package httpx provides a scanner implementation for the httpx HTTP probing tool.
package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBinary is the default httpx binary name.
	DefaultBinary = "httpx"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute

	// DefaultThreads is the default concurrency level.
	DefaultThreads = 50

	// DefaultRateLimit is the default rate limit.
	DefaultRateLimit = 150

	// DefaultRetries is the default number of retries.
	DefaultRetries = 2
)

// Scanner implements the ReconScanner interface for httpx.
type Scanner struct {
	// Configuration
	Binary  string        // Path to httpx binary (default: "httpx")
	Timeout time.Duration // Scan timeout (default: 30 minutes)
	Verbose bool          // Enable verbose output

	// Concurrency options
	Threads   int // Number of concurrent threads
	RateLimit int // Rate limit (requests per second)
	Retries   int // Number of retries

	// HTTP options
	// FollowRedirects follows every redirect, to any host. Off by default:
	// a scanned host chooses its Location header, and following it would
	// send probes to a host nobody asked to scan (api research/27 §7.4).
	FollowRedirects bool
	// FollowHostRedirects follows redirects that stay on the same host
	// (httpx -fhr). The default.
	FollowHostRedirects bool
	MaxRedirects        int      // Maximum redirects to follow
	Proxy               string   // HTTP proxy URL
	Headers             []string // Custom HTTP headers
	Method              string   // HTTP method (GET, HEAD, etc.)
	Timeout429          int      // Timeout on 429 status code

	// Probes - what to extract
	StatusCode    bool // Extract status code
	ContentLength bool // Extract content length
	Title         bool // Extract page title
	WebServer     bool // Extract web server
	TechDetect    bool // Technology detection
	CDN           bool // CDN detection
	Favicon       bool // Favicon hash
	Jarm          bool // JARM fingerprint
	ASN           bool // ASN lookup
	IP            bool // Extract IP

	// TLS options
	TLSProbe bool // Extract TLS data
	TLSGrab  bool // Grab TLS certificate

	// Filters
	MatchCodes   []int  // Match these status codes
	FilterCodes  []int  // Filter these status codes
	MatchString  string // Match response body string
	FilterString string // Filter response body string

	// Output options
	OutputFile string // Output file path
	OutputJSON bool   // JSON output
	Silent     bool   // Silent mode

	// Internal
	version string
}

// NewScanner creates a new httpx scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:              DefaultBinary,
		Timeout:             DefaultTimeout,
		Threads:             DefaultThreads,
		RateLimit:           DefaultRateLimit,
		Retries:             DefaultRetries,
		FollowHostRedirects: true,
		MaxRedirects:        10,
		StatusCode:          true,
		ContentLength:       true,
		Title:               true,
		WebServer:           true,
		TechDetect:          true,
		// What the probe learns about the server (api research/22 E5): the
		// TLS leaf certificate, the favicon hash, the JARM fingerprint and
		// the CDN/WAF in front of it. All come from the scanned host itself
		// (cdncheck data is built into httpx). ASN stays off: httpx looks it
		// up at ProjectDiscovery's API (asnmap), which would send every
		// scanned address to a third party and needs a PDCP key.
		TLSGrab:    true,
		Favicon:    true,
		Jarm:       true,
		CDN:        true,
		OutputJSON: true,
	}
}

// NewBasicProber creates a minimal prober for checking host availability.
func NewBasicProber() *Scanner {
	s := NewScanner()
	s.TechDetect = false
	s.Favicon = false
	s.ContentLength = false
	return s
}

// NewFullProber creates a comprehensive prober with all features enabled.
func NewFullProber() *Scanner {
	s := NewScanner()
	s.CDN = true
	s.Favicon = true
	s.Jarm = true
	s.ASN = true
	s.IP = true
	s.TLSProbe = true
	s.TLSGrab = true
	return s
}

// NewTechDetector creates a scanner focused on technology detection.
func NewTechDetector() *Scanner {
	s := NewScanner()
	s.TechDetect = true
	s.Favicon = true
	s.Jarm = true
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "httpx"
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Type returns the recon type.
func (s *Scanner) Type() core.ReconType {
	return core.ReconTypeHTTPProbe
}

// IsInstalled checks if httpx is installed.
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

// parseVersion extracts version from httpx output.
func parseVersion(output string) string {
	// Current releases print "[INF] Current Version: vX.Y.Z" to stderr.
	if v := core.VersionAfterLabel(output, "Current Version:"); v != "" {
		return v
	}
	// httpx version output: "httpx v1.x.x"
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "httpx") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "v") {
					return part
				}
			}
		}
	}
	return strings.TrimSpace(output)
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// Scan performs HTTP probing on the target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ReconOptions) (*core.ReconResult, error) {
	start := time.Now()

	// Build httpx arguments
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	args := s.buildArgs(target, opts)

	if s.Verbose {
		fmt.Printf("[httpx] Target: %s\n", target)
		fmt.Printf("[httpx] Args: %v\n", args)
	}

	// Execute httpx
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if opts != nil && opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		Timeout: timeout,
		Verbose: s.Verbose,
	})

	if err != nil {
		return &core.ReconResult{
			ScannerName:    s.Name(),
			ScannerVersion: s.version,
			ReconType:      s.Type(),
			Target:         target,
			StartedAt:      start.Unix(),
			FinishedAt:     time.Now().Unix(),
			DurationMs:     time.Since(start).Milliseconds(),
			ExitCode:       -1,
			Error:          err.Error(),
		}, nil
	}

	// Parse output
	liveHosts, technologies, err := s.parseOutput(execResult.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse httpx output: %w", err)
	}

	result := &core.ReconResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		ReconType:      s.Type(),
		Target:         target,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		LiveHosts:      liveHosts,
		Technologies:   technologies,
		RawOutput:      execResult.Stdout,
		ExitCode:       execResult.ExitCode,
	}

	if s.Verbose {
		fmt.Printf("[httpx] Found %d live hosts in %dms\n", len(liveHosts), result.DurationMs)
	}

	return result, nil
}

// buildArgs builds the httpx command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ReconOptions) []string {
	args := []string{}

	// Input specification
	if opts != nil && opts.InputFile != "" {
		args = append(args, "-l", opts.InputFile)
	} else if target != "" {
		args = append(args, "-u", target)
	}

	// No update check: it calls ProjectDiscovery's servers on every run.
	args = append(args, "-duc")

	// Output format - JSON for structured parsing
	if s.OutputJSON {
		args = append(args, "-json")
	}

	// Concurrency
	threads := s.Threads
	if opts != nil && opts.Threads > 0 {
		threads = opts.Threads
	}
	if threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", threads))
	}

	// Rate limit
	rateLimit := s.RateLimit
	if opts != nil && opts.RateLimit > 0 {
		rateLimit = opts.RateLimit
	}
	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	// Retries
	if s.Retries > 0 {
		args = append(args, "-retries", fmt.Sprintf("%d", s.Retries))
	}

	// HTTP options
	switch {
	case s.FollowRedirects:
		args = append(args, "-follow-redirects")
	case s.FollowHostRedirects:
		args = append(args, "-follow-host-redirects")
	}
	if (s.FollowRedirects || s.FollowHostRedirects) && s.MaxRedirects > 0 {
		args = append(args, "-max-redirects", fmt.Sprintf("%d", s.MaxRedirects))
	}
	// Not following redirects is httpx's default; it has no
	// -no-follow-redirects flag (the run failed with "flag provided but not
	// defined").

	if s.Proxy != "" {
		args = append(args, "-proxy", s.Proxy)
	}

	for _, header := range s.Headers {
		args = append(args, "-H", header)
	}

	if s.Method != "" {
		args = append(args, "-x", s.Method)
	}

	// Probes
	if s.StatusCode {
		args = append(args, "-status-code")
	}
	if s.ContentLength {
		args = append(args, "-content-length")
	}
	if s.Title {
		args = append(args, "-title")
	}
	if s.WebServer {
		args = append(args, "-web-server")
	}
	if s.TechDetect {
		args = append(args, "-tech-detect")
	}
	if s.CDN {
		args = append(args, "-cdn")
	}
	if s.Favicon {
		args = append(args, "-favicon")
	}
	if s.Jarm {
		args = append(args, "-jarm")
	}
	if s.ASN {
		args = append(args, "-asn")
	}
	if s.IP {
		args = append(args, "-ip")
	}

	// TLS
	if s.TLSProbe {
		args = append(args, "-tls-probe")
	}
	if s.TLSGrab {
		args = append(args, "-tls-grab")
	}

	// Filters
	if len(s.MatchCodes) > 0 {
		codes := make([]string, len(s.MatchCodes))
		for i, c := range s.MatchCodes {
			codes[i] = fmt.Sprintf("%d", c)
		}
		args = append(args, "-mc", strings.Join(codes, ","))
	}
	if len(s.FilterCodes) > 0 {
		codes := make([]string, len(s.FilterCodes))
		for i, c := range s.FilterCodes {
			codes[i] = fmt.Sprintf("%d", c)
		}
		args = append(args, "-fc", strings.Join(codes, ","))
	}
	if s.MatchString != "" {
		args = append(args, "-ms", s.MatchString)
	}
	if s.FilterString != "" {
		args = append(args, "-fs", s.FilterString)
	}

	// Output file
	if s.OutputFile != "" {
		args = append(args, "-o", s.OutputFile)
	}

	// Silent mode
	if s.Silent || !s.Verbose {
		args = append(args, "-silent")
	}

	// Extra args from options
	if opts != nil && len(opts.ExtraArgs) > 0 {
		args = append(args, opts.ExtraArgs...)
	}

	return args
}

// HTTPXOutput represents the JSON output from httpx.
type HTTPXOutput struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Host          string   `json:"host,omitempty"`
	Port          string   `json:"port,omitempty"`
	Scheme        string   `json:"scheme,omitempty"`
	StatusCode    int      `json:"status_code,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	Title         string   `json:"title,omitempty"`
	WebServer     string   `json:"webserver,omitempty"`
	Technologies  []string `json:"tech,omitempty"`
	CDN           bool     `json:"cdn,omitempty"`
	CDNName       string   `json:"cdn_name,omitempty"`
	CDNType       string   `json:"cdn_type,omitempty"`
	// httpx writes "a" and "cname" as arrays. Decoding "a" into a string
	// failed the whole line, so every result was dropped as "not JSON".
	HostIP       string   `json:"host_ip,omitempty"`
	A            []string `json:"a,omitempty"`
	AAAA         []string `json:"aaaa,omitempty"`
	CNAMEs       []string `json:"cname,omitempty"`
	FaviconHash  string   `json:"favicon,omitempty"`
	Jarm         string   `json:"jarm_hash,omitempty"`
	ASN          *ASNInfo `json:"asn,omitempty"`
	TLS          *TLSData `json:"tls,omitempty"`
	FinalURL     string   `json:"final_url,omitempty"`
	Method       string   `json:"method,omitempty"`
	ResponseTime string   `json:"time,omitempty"`
	Words        int      `json:"words,omitempty"`
	Lines        int      `json:"lines,omitempty"`

	// Deprecated: use HostIP or A. The parser sets it to the host's IP.
	IP string `json:"-"`
	// Deprecated: use CNAMEs. The parser sets it to the first CNAME.
	CNAME string `json:"-"`
}

// ASNInfo represents ASN information.
type ASNInfo struct {
	AsNumber  string   `json:"as_number"`
	AsName    string   `json:"as_name"`
	AsCountry string   `json:"as_country"`
	AsRange   []string `json:"as_range"`
}

// TLSData represents TLS certificate data (httpx -tls-grab, the tlsx
// response).
type TLSData struct {
	TLSVersion       string          `json:"tls_version"`
	CipherSuite      string          `json:"cipher"`
	DNSNames         []string        `json:"subject_an"`
	CommonName       string          `json:"subject_cn"`
	Organization     []string        `json:"subject_org"`
	IssuerCommonName string          `json:"issuer_cn"`
	IssuerOrg        []string        `json:"issuer_org"`
	Serial           string          `json:"serial"`
	NotBefore        string          `json:"not_before"`
	NotAfter         string          `json:"not_after"`
	Fingerprint      TLSFingerprints `json:"fingerprint_hash"`
	SelfSigned       bool            `json:"self_signed"`
	Expired          bool            `json:"expired"`
	Mismatched       bool            `json:"mismatched"`
	Wildcard         bool            `json:"wildcard_certificate"`
}

// TLSFingerprints are the certificate's hashes.
type TLSFingerprints struct {
	SHA256 string `json:"sha256"`
}

// leaf is the certificate as core.TLSLeaf, or nil without a SHA-256
// fingerprint (its identity). Values are passed on as httpx wrote them; the
// CTIS converter bounds and validates them.
func (t *TLSData) leaf() *core.TLSLeaf {
	if t == nil || strings.TrimSpace(t.Fingerprint.SHA256) == "" {
		return nil
	}
	l := &core.TLSLeaf{
		SubjectCN:         t.CommonName,
		SANs:              t.DNSNames,
		IssuerCN:          t.IssuerCommonName,
		SerialNumber:      t.Serial,
		FingerprintSHA256: t.Fingerprint.SHA256,
		SelfSigned:        t.SelfSigned,
		Expired:           t.Expired,
		Wildcard:          t.Wildcard,
		Mismatched:        t.Mismatched,
	}
	if len(t.IssuerOrg) > 0 {
		l.IssuerOrg = t.IssuerOrg[0]
	}
	if ts, err := time.Parse(time.RFC3339, t.NotBefore); err == nil {
		l.NotBefore = ts
	}
	if ts, err := time.Parse(time.RFC3339, t.NotAfter); err == nil {
		l.NotAfter = ts
	}
	return l
}

// parseOutput parses httpx JSON output.
func (s *Scanner) parseOutput(data []byte) ([]core.LiveHost, []core.Technology, error) {
	var liveHosts []core.LiveHost
	var technologies []core.Technology
	seen := make(map[string]bool)
	techSeen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var output HTTPXOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If not JSON, skip
			continue
		}

		// Deduplicate by URL
		if seen[output.URL] {
			continue
		}
		seen[output.URL] = true

		// Parse port
		port := 0
		if output.Port != "" {
			_, _ = fmt.Sscanf(output.Port, "%d", &port)
		}

		// Parse response time
		var responseTime int64
		if output.ResponseTime != "" {
			// Format: "123ms" or "1.23s"
			if strings.HasSuffix(output.ResponseTime, "ms") {
				_, _ = fmt.Sscanf(output.ResponseTime, "%dms", &responseTime)
			} else if strings.HasSuffix(output.ResponseTime, "s") {
				var seconds float64
				_, _ = fmt.Sscanf(output.ResponseTime, "%fs", &seconds)
				responseTime = int64(seconds * 1000)
			}
		}

		// Get TLS version
		tlsVersion := ""
		if output.TLS != nil {
			tlsVersion = output.TLS.TLSVersion
		}

		// Get redirect URL
		redirect := ""
		if output.FinalURL != "" && output.FinalURL != output.URL {
			redirect = output.FinalURL
		}

		// CDN name
		cdn := ""
		if output.CDN {
			cdn = output.CDNName
		}

		ip := output.HostIP
		if ip == "" && len(output.A) > 0 {
			ip = output.A[0]
		}
		output.IP = ip
		if len(output.CNAMEs) > 0 {
			output.CNAME = output.CNAMEs[0]
		}

		liveHost := core.LiveHost{
			URL:           output.URL,
			Host:          output.Host,
			IP:            ip,
			Port:          port,
			Scheme:        output.Scheme,
			StatusCode:    output.StatusCode,
			ContentLength: output.ContentLength,
			Title:         output.Title,
			WebServer:     output.WebServer,
			ContentType:   output.ContentType,
			Technologies:  output.Technologies,
			CDN:           cdn,
			TLSVersion:    tlsVersion,
			Redirect:      redirect,
			ResponseTime:  responseTime,
			TLS:           output.TLS.leaf(),
			FaviconMMH3:   output.FaviconHash,
			JARM:          output.Jarm,
		}
		if output.CDN {
			liveHost.CDNType = output.CDNType
		}
		if output.ASN != nil {
			liveHost.ASN = &core.ASN{Number: output.ASN.AsNumber, Org: output.ASN.AsName, Country: output.ASN.AsCountry}
		}

		liveHosts = append(liveHosts, liveHost)

		// Extract technologies
		for _, tech := range output.Technologies {
			if !techSeen[tech] {
				techSeen[tech] = true
				technologies = append(technologies, core.Technology{
					Name: tech,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return liveHosts, technologies, nil
}

// GetLiveHosts performs scan and returns only live hosts.
func (s *Scanner) GetLiveHosts(ctx context.Context, target string, opts *core.ReconOptions) ([]string, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	var urls []string
	for _, h := range result.LiveHosts {
		urls = append(urls, h.URL)
	}

	return urls, nil
}

// GetLiveHostsWithStatus performs scan and returns hosts with their status codes.
func (s *Scanner) GetLiveHostsWithStatus(ctx context.Context, target string, opts *core.ReconOptions) (map[string]int, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	hostStatus := make(map[string]int)
	for _, h := range result.LiveHosts {
		hostStatus[h.URL] = h.StatusCode
	}

	return hostStatus, nil
}

// FilterByStatusCode filters live hosts by status code.
func (s *Scanner) FilterByStatusCode(hosts []core.LiveHost, codes []int) []core.LiveHost {
	codeSet := make(map[int]bool)
	for _, c := range codes {
		codeSet[c] = true
	}

	var filtered []core.LiveHost
	for _, h := range hosts {
		if codeSet[h.StatusCode] {
			filtered = append(filtered, h)
		}
	}

	return filtered
}

// Limits returns the scanner's own request rate and concurrency (0: none
// set, unlimited). A scan may only lower them (recon.Scanner).
func (s *Scanner) Limits() (rate, concurrency int) {
	return s.RateLimit, s.Threads
}
