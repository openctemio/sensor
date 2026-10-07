// Package katana provides a scanner implementation for the katana web crawler.
package katana

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

const (
	// DefaultBinary is the default katana binary name.
	DefaultBinary = "katana"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute

	// DefaultConcurrency is the default concurrency level.
	DefaultConcurrency = 10

	// DefaultDepth is the default crawl depth.
	DefaultDepth = 3

	// DefaultRateLimit is the default rate limit.
	DefaultRateLimit = 150
)

// ScopeType represents the scope constraint type.
type ScopeType string

const (
	ScopeDN   ScopeType = "dn"   // Domain name
	ScopeRDN  ScopeType = "rdn"  // Root domain name
	ScopeFQDN ScopeType = "fqdn" // Fully qualified domain name
)

// Scanner implements the ReconScanner interface for katana.
type Scanner struct {
	// Configuration
	Binary  string        // Path to katana binary (default: "katana")
	Timeout time.Duration // Scan timeout (default: 30 minutes)
	Verbose bool          // Enable verbose output

	// Crawl options
	Concurrency int       // Number of concurrent crawlers
	Depth       int       // Maximum crawl depth
	MaxURLs     int       // Keep at most this many URLs per start URL (0: all)
	JSCrawl     bool      // Enable JavaScript crawling
	Scope       ScopeType // Scope constraint (dn, rdn, fqdn)
	FieldScope  string    // Custom scope field
	// FollowRedirects lets katana follow redirects, to any host. Off by
	// default (-dr): a crawl stays on the hosts its scope names.
	FollowRedirects bool

	// Rate limiting
	RateLimit       int           // Rate limit per second
	RateLimitMinute int           // Rate limit per minute
	Delay           time.Duration // Delay between requests

	// Discovery options
	KnownFiles string   // Known files to discover (robots, sitemap)
	FormFill   bool     // Enable form filling
	Extensions []string // Extensions to filter
	FormPaths  []string // Paths to exclude from forms

	// Output options
	OutputFile       string // Output file path
	OutputJSON       bool   // JSON output
	OutputAll        bool   // Deprecated: katana has no -output-all flag; ignored
	Silent           bool   // Silent mode
	StoreResponse    bool   // Store HTTP response
	StoreResponseDir string // Directory to store responses

	// Filter options
	FilterExtension []string // Extensions to filter out
	MatchExtension  []string // Extensions to match
	FilterRegex     string   // Regex to filter URLs
	MatchRegex      string   // Regex to match URLs

	// Headless options
	Headless        bool   // Enable headless browser
	HeadlessOptions string // Headless browser options

	// Proxy
	Proxy string // HTTP proxy URL

	// WebScope is the job's web scope (webscope.go): flags and a filter
	// that keep the crawl inside it.
	WebScope *webscope.Scope `json:",omitempty"`

	// Internal
	version string
}

// NewScanner creates a new katana scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:      DefaultBinary,
		Timeout:     DefaultTimeout,
		Concurrency: DefaultConcurrency,
		Depth:       DefaultDepth,
		RateLimit:   DefaultRateLimit,
		JSCrawl:     true,
		// Crawl the target host only (api research/27 §7.4). rdn crawled
		// every host under the registrable domain: a page on one name
		// steered the crawler to names nobody asked to scan.
		Scope:      ScopeFQDN,
		OutputJSON: true,
	}
}

// NewBasicCrawler creates a minimal crawler for quick discovery.
func NewBasicCrawler() *Scanner {
	s := NewScanner()
	s.Depth = 2
	s.JSCrawl = false
	s.Concurrency = 5
	return s
}

// NewDeepCrawler creates a comprehensive crawler for thorough discovery.
func NewDeepCrawler() *Scanner {
	s := NewScanner()
	s.Depth = 5
	s.JSCrawl = true
	s.FormFill = true
	s.KnownFiles = "all"
	s.Concurrency = 20
	return s
}

// NewHeadlessCrawler creates a crawler with headless browser support.
func NewHeadlessCrawler() *Scanner {
	s := NewScanner()
	s.Headless = true
	s.JSCrawl = true
	s.Depth = 3
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "katana"
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// SetVersion sets the version IsInstalled found (a tool child that did not
// probe the binary itself reports the parent's).
func (s *Scanner) SetVersion(v string) { s.version = v }

// Type returns the recon type.
func (s *Scanner) Type() core.ReconType {
	return core.ReconTypeURLCrawl
}

// IsInstalled checks if katana is installed.
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

// parseVersion extracts version from katana output.
func parseVersion(output string) string {
	// Current releases print "[INF] Current Version: vX.Y.Z" to stderr.
	// katana 1.7 spells it "Current version:".
	for _, label := range []string{"Current Version:", "Current version:"} {
		if v := core.VersionAfterLabel(output, label); v != "" {
			return v
		}
	}
	// katana version output: "katana v1.x.x"
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "katana") {
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

// Scan performs URL crawling on the target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ReconOptions) (*core.ReconResult, error) {
	start := time.Now()

	// Build katana arguments
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	args := s.buildArgs(target, opts)

	if s.Verbose {
		fmt.Printf("[katana] Target: %s\n", target)
		fmt.Printf("[katana] Args: %v\n", args)
	}

	// Execute katana
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
	urls, err := s.parseOutput(execResult.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse katana output: %w", err)
	}
	if s.FieldScope == "" && s.Scope == ScopeFQDN {
		urls = sameHostURLs(target, urls)
	}
	urls = s.inWebScope(target, urls)
	if s.MaxURLs > 0 && len(urls) > s.MaxURLs {
		urls = urls[:s.MaxURLs]
	}

	result := &core.ReconResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		ReconType:      s.Type(),
		Target:         target,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		URLs:           urls,
		RawOutput:      execResult.Stdout,
		ExitCode:       execResult.ExitCode,
	}

	if s.Verbose {
		fmt.Printf("[katana] Found %d URLs in %dms\n", len(urls), result.DurationMs)
	}

	return result, nil
}

// sameHostURLs keeps the URLs on the target's host. With the fqdn scope
// katana should report nothing else; the filter keeps a page that links
// elsewhere from planting another host's URLs in the results whatever the
// crawler does. A target without a host keeps every URL.
func sameHostURLs(target string, urls []core.DiscoveredURL) []core.DiscoveredURL {
	host := urlHost(target)
	if host == "" {
		return urls
	}
	kept := urls[:0]
	for _, u := range urls {
		if urlHost(u.URL) == host {
			kept = append(kept, u)
		}
	}
	return kept
}

// urlHost is the lower-case host of a URL or bare host[:port], without port
// or trailing dot ("" when there is none).
func urlHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// buildArgs builds the katana command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ReconOptions) []string {
	args := []string{}

	// Input specification
	if opts != nil && opts.InputFile != "" {
		args = append(args, "-list", opts.InputFile)
	} else if target != "" {
		args = append(args, "-u", target)
	}

	// No update check: it calls ProjectDiscovery's servers on every run.
	args = append(args, "-duc")

	// Output format - JSON for structured parsing
	if s.OutputJSON {
		args = append(args, "-jsonl")
	}

	// Concurrency
	concurrency := s.Concurrency
	if opts != nil && opts.Threads > 0 {
		concurrency = opts.Threads
	}
	if concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", concurrency))
	}

	// Depth
	if s.Depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", s.Depth))
	}

	// Rate limiting
	rateLimit := s.RateLimit
	if opts != nil && opts.RateLimit > 0 {
		rateLimit = opts.RateLimit
	}
	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}
	if s.RateLimitMinute > 0 {
		args = append(args, "-rlm", fmt.Sprintf("%d", s.RateLimitMinute))
	}
	if s.Delay > 0 {
		// -rd is in seconds (katana's -delay); milliseconds made a 1s
		// delay 1000s. Round up so a sub-second delay is not dropped.
		args = append(args, "-rd", fmt.Sprintf("%d", int((s.Delay+time.Second-1)/time.Second)))
	}

	// JavaScript crawling
	if s.JSCrawl {
		args = append(args, "-js-crawl")
	}

	// Scope
	// dn/rdn/fqdn are -fs (field-scope) values. -cs is a crawl-scope
	// regex: "-cs rdn" kept only URLs containing the text "rdn". A custom
	// FieldScope (field name or regex) replaces the preset.
	switch {
	case s.FieldScope != "":
		args = append(args, "-fs", s.FieldScope)
	case s.Scope != "":
		args = append(args, "-fs", string(s.Scope))
	}
	// Redirects off (-dr): katana follows a redirect whatever the scope, so
	// an in-scope link that redirects to another host made a request to that
	// host (measured on katana v1.7.0: with -fs fqdn a link to /local that
	// redirected to a second host was fetched there; dropping the URL from
	// the results afterwards does not undo the request). In-scope links are
	// still crawled.
	if !s.FollowRedirects {
		args = append(args, "-dr")
	}
	args = append(args, s.scopeArgs()...)

	// Discovery options
	if s.KnownFiles != "" {
		args = append(args, "-kf", s.KnownFiles)
	}
	if s.FormFill {
		args = append(args, "-aff") // -automatic-form-fill; there is no -form-fill
	}

	// Filter extensions
	if len(s.FilterExtension) > 0 {
		args = append(args, "-ef", strings.Join(s.FilterExtension, ","))
	}
	if len(s.MatchExtension) > 0 {
		args = append(args, "-em", strings.Join(s.MatchExtension, ","))
	}

	// Regex filters
	if s.FilterRegex != "" {
		args = append(args, "-fr", s.FilterRegex)
	}
	if s.MatchRegex != "" {
		args = append(args, "-mr", s.MatchRegex)
	}

	// Headless options
	if s.Headless {
		args = append(args, "-headless")
		if s.HeadlessOptions != "" {
			args = append(args, "-headless-options", s.HeadlessOptions)
		}
	}

	// Proxy
	if s.Proxy != "" {
		args = append(args, "-proxy", s.Proxy)
	}

	// Store response
	if s.StoreResponse {
		args = append(args, "-sr")
		if s.StoreResponseDir != "" {
			args = append(args, "-srd", s.StoreResponseDir)
		}
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

// KatanaOutput represents the JSON output from katana.
//
// katana -jsonl writes the request and the response as objects. Decoding
// "request" into a string failed, so every line was taken for a plain URL
// and the whole JSON text was reported as the discovered URL.
type KatanaOutput struct {
	Request  KatanaRequest   `json:"request"`
	Response *KatanaResponse `json:"response,omitempty"`
	Error    string          `json:"error,omitempty"`

	// Deprecated: use Request.Endpoint. The flat fields below are filled
	// from Request and Response by Flatten (the parser calls it).
	URL string `json:"-"`
	// Deprecated: use Request.Endpoint.
	Endpoint string `json:"-"`
	// Deprecated: use Request.Source.
	Source string `json:"-"`
	// Deprecated: use Request.Method.
	Method string `json:"-"`
	// Deprecated: use Request.Depth.
	Depth int `json:"-"`
	// Deprecated: use Request.Tag.
	Tag string `json:"-"`
	// Deprecated: use Response.StatusCode.
	Status int `json:"-"`
}

// Flatten fills the deprecated flat fields from Request and Response.
func (o *KatanaOutput) Flatten() {
	o.URL = o.Request.Endpoint
	o.Endpoint = o.Request.Endpoint
	o.Source = o.Request.Source
	o.Method = o.Request.Method
	o.Depth = o.Request.Depth
	o.Tag = o.Request.Tag
	if o.Response != nil {
		o.Status = o.Response.StatusCode
	}
}

// KatanaRequest is the request katana made for a discovered endpoint.
type KatanaRequest struct {
	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Source    string `json:"source,omitempty"`
	Depth     int    `json:"depth,omitempty"`
}

// KatanaResponse is the response katana received.
type KatanaResponse struct {
	StatusCode int `json:"status_code,omitempty"`
}

// parseOutput parses katana JSON output.
func (s *Scanner) parseOutput(data []byte) ([]core.DiscoveredURL, error) {
	var urls []core.DiscoveredURL
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var output KatanaOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If not JSON, treat as plain URL
			endpoint := line
			if !seen[endpoint] {
				seen[endpoint] = true
				urls = append(urls, core.DiscoveredURL{
					URL:       endpoint,
					Source:    "crawl",
					Extension: getExtension(endpoint),
				})
			}
			continue
		}

		output.Flatten()
		endpoint := output.Request.Endpoint
		if endpoint == "" {
			continue
		}
		// A request that got no response (refused, timed out) is not a
		// discovered endpoint.
		if output.Response == nil && output.Error != "" {
			continue
		}
		status := 0
		if output.Response != nil {
			status = output.Response.StatusCode
		}

		// Deduplicate
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true

		// Determine URL type
		urlType := determineURLType(endpoint, output.Request.Tag)

		urls = append(urls, core.DiscoveredURL{
			URL:        endpoint,
			Method:     output.Request.Method,
			Source:     output.Request.Source,
			StatusCode: status,
			Depth:      output.Request.Depth,
			Type:       urlType,
			Extension:  getExtension(endpoint),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// getExtension extracts file extension from URL.
func getExtension(endpoint string) string {
	// Remove query string
	if idx := strings.Index(endpoint, "?"); idx != -1 {
		endpoint = endpoint[:idx]
	}
	// Get extension
	ext := filepath.Ext(endpoint)
	if ext != "" {
		return strings.TrimPrefix(ext, ".")
	}
	return ""
}

// determineURLType determines the type of URL.
func determineURLType(endpoint string, tag string) string {
	// Check tag first
	switch tag {
	case "form":
		return "form"
	case "script":
		return "script"
	case "a":
		return "link"
	}

	// Check URL patterns
	endpoint = strings.ToLower(endpoint)

	// API patterns
	if strings.Contains(endpoint, "/api/") ||
		strings.Contains(endpoint, "/v1/") ||
		strings.Contains(endpoint, "/v2/") ||
		strings.Contains(endpoint, "/graphql") ||
		strings.Contains(endpoint, "/rest/") {
		return "api"
	}

	// Static resources
	ext := getExtension(endpoint)
	switch ext {
	case "js":
		return "script"
	case "css":
		return "style"
	case "jpg", "jpeg", "png", "gif", "svg", "ico", "webp":
		return "image"
	case "pdf", "doc", "docx", "xls", "xlsx":
		return "document"
	case "json", "xml":
		return "data"
	}

	return "endpoint"
}

// GetURLs performs scan and returns only the URL list.
func (s *Scanner) GetURLs(ctx context.Context, target string, opts *core.ReconOptions) ([]string, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	var urls []string
	for _, u := range result.URLs {
		urls = append(urls, u.URL)
	}

	return urls, nil
}

// GetAPIEndpoints performs scan and returns only API endpoints.
func (s *Scanner) GetAPIEndpoints(ctx context.Context, target string, opts *core.ReconOptions) ([]core.DiscoveredURL, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	var apis []core.DiscoveredURL
	for _, u := range result.URLs {
		if u.Type == "api" {
			apis = append(apis, u)
		}
	}

	return apis, nil
}

// FilterByExtension filters URLs by file extension.
func (s *Scanner) FilterByExtension(urls []core.DiscoveredURL, extensions []string) []core.DiscoveredURL {
	extSet := make(map[string]bool)
	for _, e := range extensions {
		extSet[strings.ToLower(e)] = true
	}

	var filtered []core.DiscoveredURL
	for _, u := range urls {
		if extSet[strings.ToLower(u.Extension)] {
			filtered = append(filtered, u)
		}
	}

	return filtered
}

// FilterByType filters URLs by type.
func (s *Scanner) FilterByType(urls []core.DiscoveredURL, urlType string) []core.DiscoveredURL {
	var filtered []core.DiscoveredURL
	for _, u := range urls {
		if u.Type == urlType {
			filtered = append(filtered, u)
		}
	}
	return filtered
}

// Limits returns the scanner's own request rate and concurrency (0: none
// set, unlimited). A scan may only lower them (recon.Scanner).
func (s *Scanner) Limits() (rate, concurrency int) {
	return s.RateLimit, s.Concurrency
}
