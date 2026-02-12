//go:build hybrid

package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	naaburunner "github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// =============================================================================
// HYBRID TOOL EXECUTOR (Build with -tags hybrid)
// Uses Go libraries when available, falls back to CLI
// =============================================================================

// HybridModeEnabled indicates hybrid library mode is available.
const HybridModeEnabled = true

// =============================================================================
// SUBFINDER - Library Implementation
// =============================================================================

// SubfinderLibExecutor uses the subfinder library directly.
type SubfinderLibExecutor struct {
	verbose bool
}

func NewSubfinderLibExecutor(verbose bool) *SubfinderLibExecutor {
	return &SubfinderLibExecutor{verbose: verbose}
}

func (t *SubfinderLibExecutor) Name() string {
	return "subfinder"
}

func (t *SubfinderLibExecutor) Capabilities() []string {
	return []string{"subdomain"}
}

func (t *SubfinderLibExecutor) IsInstalled(ctx context.Context) (bool, string, error) {
	// Library is always "installed" if we can import it
	return true, "library-v2", nil
}

func (t *SubfinderLibExecutor) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Configure subfinder options
	runnerOpts := &runner.Options{
		Threads:            opts.Threads,
		Timeout:            opts.Timeout,
		MaxEnumerationTime: opts.Timeout / 60, // Convert to minutes
		Resolvers:          resolve.DefaultResolvers,
	}

	if runnerOpts.Threads == 0 {
		runnerOpts.Threads = 10
	}
	if runnerOpts.MaxEnumerationTime == 0 {
		runnerOpts.MaxEnumerationTime = 10
	}

	r, err := runner.NewRunner(runnerOpts)
	if err != nil {
		return &ToolResult{
			Tool:     "subfinder",
			Success:  false,
			Error:    fmt.Sprintf("failed to create runner: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Collect results
	var subdomains []string
	outputCallback := func(s *resolve.HostEntry) {
		subdomains = append(subdomains, s.Host)
	}

	// Run enumeration
	targets := []string{opts.Target}
	if len(opts.Targets) > 0 {
		targets = opts.Targets
	}

	err = r.EnumerateMultipleDomains(ctx, targets, outputCallback)
	if err != nil {
		return &ToolResult{
			Tool:     "subfinder",
			Success:  false,
			Error:    fmt.Sprintf("enumeration failed: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Convert to JSON output format for compatibility
	output := subdomainsToJSON(subdomains)

	return &ToolResult{
		Tool:      "subfinder",
		Success:   true,
		Output:    output,
		Parsed:    subdomains,
		Duration:  time.Since(startTime).Milliseconds(),
		ItemCount: len(subdomains),
	}, nil
}

func subdomainsToJSON(subdomains []string) []byte {
	var lines []string
	for _, s := range subdomains {
		lines = append(lines, fmt.Sprintf(`{"host":"%s"}`, s))
	}
	return []byte(strings.Join(lines, "\n"))
}

// =============================================================================
// DNSX - Library Implementation
// =============================================================================

// DNSXLibExecutor uses the dnsx library directly.
type DNSXLibExecutor struct {
	verbose bool
}

func NewDNSXLibExecutor(verbose bool) *DNSXLibExecutor {
	return &DNSXLibExecutor{verbose: verbose}
}

func (t *DNSXLibExecutor) Name() string {
	return "dnsx"
}

func (t *DNSXLibExecutor) Capabilities() []string {
	return []string{"dns"}
}

func (t *DNSXLibExecutor) IsInstalled(ctx context.Context) (bool, string, error) {
	return true, "library-v1", nil
}

func (t *DNSXLibExecutor) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Create DNSX client with default options
	dnsxOpts := dnsx.DefaultOptions
	dnsxOpts.MaxRetries = 3

	client, err := dnsx.New(dnsxOpts)
	if err != nil {
		return &ToolResult{
			Tool:     "dnsx",
			Success:  false,
			Error:    fmt.Sprintf("failed to create client: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Query targets
	targets := []string{opts.Target}
	if len(opts.Targets) > 0 {
		targets = opts.Targets
	}

	var results []dnsResult
	for _, target := range targets {
		// Query A records
		aRecords, err := client.Lookup(target)
		if err == nil && len(aRecords) > 0 {
			results = append(results, dnsResult{
				Host: target,
				A:    aRecords,
			})
		}

		// Query CNAME if needed
		cname, err := client.CNAME(target)
		if err == nil && cname != "" {
			// Update or create result
			found := false
			for i := range results {
				if results[i].Host == target {
					results[i].CNAME = []string{cname}
					found = true
					break
				}
			}
			if !found {
				results = append(results, dnsResult{
					Host:  target,
					CNAME: []string{cname},
				})
			}
		}
	}

	// Convert to JSON
	output := dnsResultsToJSON(results)

	return &ToolResult{
		Tool:      "dnsx",
		Success:   true,
		Output:    output,
		Parsed:    results,
		Duration:  time.Since(startTime).Milliseconds(),
		ItemCount: len(results),
	}, nil
}

type dnsResult struct {
	Host  string   `json:"host"`
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

func dnsResultsToJSON(results []dnsResult) []byte {
	var lines []string
	for _, r := range results {
		line := fmt.Sprintf(`{"host":"%s"`, r.Host)
		if len(r.A) > 0 {
			line += fmt.Sprintf(`,"a":["%s"]`, strings.Join(r.A, `","`))
		}
		if len(r.CNAME) > 0 {
			line += fmt.Sprintf(`,"cname":["%s"]`, strings.Join(r.CNAME, `","`))
		}
		line += "}"
		lines = append(lines, line)
	}
	return []byte(strings.Join(lines, "\n"))
}

// =============================================================================
// NAABU - Library Implementation
// =============================================================================

// NaabuLibExecutor uses the naabu library directly.
type NaabuLibExecutor struct {
	verbose bool
}

func NewNaabuLibExecutor(verbose bool) *NaabuLibExecutor {
	return &NaabuLibExecutor{verbose: verbose}
}

func (t *NaabuLibExecutor) Name() string {
	return "naabu"
}

func (t *NaabuLibExecutor) Capabilities() []string {
	return []string{"portscan"}
}

func (t *NaabuLibExecutor) IsInstalled(ctx context.Context) (bool, string, error) {
	// Check if libpcap is available (required for naabu library)
	_, err := exec.LookPath("naabu")
	if err != nil {
		return false, "", fmt.Errorf("naabu binary not found and libpcap may not be available")
	}
	return true, "library-v2", nil
}

func (t *NaabuLibExecutor) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Collect targets
	targets := goflags.StringSlice{opts.Target}
	if len(opts.Targets) > 0 {
		targets = opts.Targets
	}

	// Configure naabu options
	naabuOpts := naaburunner.Options{
		Host:     targets,
		ScanType: "s", // SYN scan
		Ports:    "top-1000",
	}

	// Collect results via callback
	var portResults []portResult
	naabuOpts.OnResult = func(hr *result.HostResult) {
		for _, port := range hr.Ports {
			portResults = append(portResults, portResult{
				Host: hr.Host,
				IP:   hr.IP,
				Port: port.Port,
			})
		}
	}

	// Create and run scanner
	r, err := naaburunner.NewRunner(&naabuOpts)
	if err != nil {
		return &ToolResult{
			Tool:     "naabu",
			Success:  false,
			Error:    fmt.Sprintf("failed to create runner: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}
	defer r.Close()

	err = r.RunEnumeration(ctx)
	if err != nil {
		return &ToolResult{
			Tool:     "naabu",
			Success:  false,
			Error:    fmt.Sprintf("scan failed: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Convert to JSON
	output := portResultsToJSON(portResults)

	return &ToolResult{
		Tool:      "naabu",
		Success:   true,
		Output:    output,
		Parsed:    portResults,
		Duration:  time.Since(startTime).Milliseconds(),
		ItemCount: len(portResults),
	}, nil
}

type portResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func portResultsToJSON(results []portResult) []byte {
	var lines []string
	for _, r := range results {
		lines = append(lines, fmt.Sprintf(`{"host":"%s","ip":"%s","port":%d}`, r.Host, r.IP, r.Port))
	}
	return []byte(strings.Join(lines, "\n"))
}

// =============================================================================
// HTTPX - Library Implementation
// =============================================================================

// HTTPXLibExecutor uses the httpx library directly.
type HTTPXLibExecutor struct {
	verbose bool
}

func NewHTTPXLibExecutor(verbose bool) *HTTPXLibExecutor {
	return &HTTPXLibExecutor{verbose: verbose}
}

func (t *HTTPXLibExecutor) Name() string {
	return "httpx"
}

func (t *HTTPXLibExecutor) Capabilities() []string {
	return []string{"http", "tech-detect"}
}

func (t *HTTPXLibExecutor) IsInstalled(ctx context.Context) (bool, string, error) {
	return true, "library-v1", nil
}

func (t *HTTPXLibExecutor) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Configure httpx options
	httpxOpts := httpx.DefaultOptions
	httpxOpts.Threads = opts.Threads
	httpxOpts.Timeout = time.Duration(opts.Timeout) * time.Second

	if httpxOpts.Threads == 0 {
		httpxOpts.Threads = 25
	}
	if httpxOpts.Timeout == 0 {
		httpxOpts.Timeout = 30 * time.Second
	}

	client, err := httpx.New(&httpxOpts)
	if err != nil {
		return &ToolResult{
			Tool:     "httpx",
			Success:  false,
			Error:    fmt.Sprintf("failed to create client: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Probe targets
	targets := []string{opts.Target}
	if len(opts.Targets) > 0 {
		targets = opts.Targets
	}

	var results []httpxResult
	for _, target := range targets {
		// Ensure URL has scheme
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			// Try both
			for _, scheme := range []string{"https://", "http://"} {
				url := scheme + target
				resp, err := client.Do(client.NewRequest(ctx, "GET", url))
				if err == nil && resp != nil {
					results = append(results, httpxResult{
						URL:        url,
						StatusCode: resp.StatusCode,
						Title:      resp.Title,
						Server:     resp.GetHeader("Server"),
					})
					break
				}
			}
		} else {
			resp, err := client.Do(client.NewRequest(ctx, "GET", target))
			if err == nil && resp != nil {
				results = append(results, httpxResult{
					URL:        target,
					StatusCode: resp.StatusCode,
					Title:      resp.Title,
					Server:     resp.GetHeader("Server"),
				})
			}
		}
	}

	// Convert to JSON
	output := httpxResultsToJSON(results)

	return &ToolResult{
		Tool:      "httpx",
		Success:   true,
		Output:    output,
		Parsed:    results,
		Duration:  time.Since(startTime).Milliseconds(),
		ItemCount: len(results),
	}, nil
}

type httpxResult struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status-code"`
	Title      string   `json:"title,omitempty"`
	Server     string   `json:"webserver,omitempty"`
	Tech       []string `json:"tech,omitempty"`
}

func httpxResultsToJSON(results []httpxResult) []byte {
	var lines []string
	for _, r := range results {
		line := fmt.Sprintf(`{"url":"%s","status-code":%d`, r.URL, r.StatusCode)
		if r.Title != "" {
			line += fmt.Sprintf(`,"title":"%s"`, r.Title)
		}
		if r.Server != "" {
			line += fmt.Sprintf(`,"webserver":"%s"`, r.Server)
		}
		line += "}"
		lines = append(lines, line)
	}
	return []byte(strings.Join(lines, "\n"))
}

// =============================================================================
// KATANA - Library Implementation
// =============================================================================

// KatanaLibExecutor uses the katana library directly.
type KatanaLibExecutor struct {
	verbose bool
}

func NewKatanaLibExecutor(verbose bool) *KatanaLibExecutor {
	return &KatanaLibExecutor{verbose: verbose}
}

func (t *KatanaLibExecutor) Name() string {
	return "katana"
}

func (t *KatanaLibExecutor) Capabilities() []string {
	return []string{"crawler", "url-discovery"}
}

func (t *KatanaLibExecutor) IsInstalled(ctx context.Context) (bool, string, error) {
	return true, "library-v1", nil
}

func (t *KatanaLibExecutor) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Collect results
	var urls []string
	var resultsMu = make(chan string, 1000)

	// Configure katana options
	katanaOpts := &types.Options{
		MaxDepth:     3,
		FieldScope:   "rdn",
		BodyReadSize: 2 * 1024 * 1024,
		RateLimit:    opts.RateLimit,
		Strategy:     "depth-first",
		Timeout:      opts.Timeout,
		OnResult: func(r output.Result) {
			select {
			case resultsMu <- r.Request.URL:
			default:
			}
		},
	}

	if katanaOpts.RateLimit == 0 {
		katanaOpts.RateLimit = 150
	}
	if katanaOpts.Timeout == 0 {
		katanaOpts.Timeout = 300
	}

	crawlerOpts, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return &ToolResult{
			Tool:     "katana",
			Success:  false,
			Error:    fmt.Sprintf("failed to create crawler options: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}
	defer crawlerOpts.Close()

	crawler, err := standard.New(crawlerOpts)
	if err != nil {
		return &ToolResult{
			Tool:     "katana",
			Success:  false,
			Error:    fmt.Sprintf("failed to create crawler: %v", err),
			Duration: time.Since(startTime).Milliseconds(),
		}, nil
	}
	defer crawler.Close()

	// Start collecting URLs in background
	done := make(chan struct{})
	go func() {
		for url := range resultsMu {
			urls = append(urls, url)
		}
		close(done)
	}()

	// Crawl target
	target := opts.Target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	err = crawler.Crawl(target)
	close(resultsMu)
	<-done

	if err != nil {
		if len(urls) == 0 {
			return &ToolResult{
				Tool:     "katana",
				Success:  false,
				Error:    fmt.Sprintf("crawl failed: %v", err),
				Duration: time.Since(startTime).Milliseconds(),
			}, nil
		}
	}

	output := urlsToJSON(urls)

	return &ToolResult{
		Tool:      "katana",
		Success:   true,
		Output:    output,
		Parsed:    urls,
		Duration:  time.Since(startTime).Milliseconds(),
		ItemCount: len(urls),
	}, nil
}

func urlsToJSON(urls []string) []byte {
	var lines []string
	for _, u := range urls {
		lines = append(lines, fmt.Sprintf(`{"request":{"url":"%s"}}`, u))
	}
	return []byte(strings.Join(lines, "\n"))
}

// =============================================================================
// HYBRID RECON CONFIG
// =============================================================================

// HybridReconConfig extends ReconConfig with library preference settings.
type HybridReconConfig struct {
	*ReconConfig

	// Prefer library over CLI when available
	PreferLibrary bool

	// Per-tool library preference (overrides global PreferLibrary)
	SubfinderUseLib bool
	DNSXUseLib      bool
	NaabuUseLib     bool
	HTTPXUseLib     bool
	KatanaUseLib    bool
}

// DefaultHybridReconConfig returns sensible defaults for hybrid mode.
func DefaultHybridReconConfig() *HybridReconConfig {
	return &HybridReconConfig{
		ReconConfig:     DefaultReconConfig(),
		PreferLibrary:   true,
		SubfinderUseLib: true,
		DNSXUseLib:      true,
		NaabuUseLib:     false, // Requires libpcap, CLI more portable
		HTTPXUseLib:     true,
		KatanaUseLib:    true,
	}
}

// CreateHybridTools creates tool executors with library preference.
func CreateHybridTools(cfg *HybridReconConfig, verbose bool) map[string]ToolExecutor {
	tools := make(map[string]ToolExecutor)

	if cfg.SubfinderEnabled {
		if cfg.PreferLibrary && cfg.SubfinderUseLib {
			tools["subfinder"] = NewSubfinderLibExecutor(verbose)
		} else {
			tools["subfinder"] = &cliToolExecutor{
				name:         "subfinder",
				binary:       getPathOrDefault("subfinder", cfg.SubfinderPath),
				capabilities: []string{"subdomain"},
				outputFlag:   "-oJ",
				targetFlag:   "-d",
				defaultArgs:  []string{"-silent"},
			}
		}
	}

	if cfg.DNSXEnabled {
		if cfg.PreferLibrary && cfg.DNSXUseLib {
			tools["dnsx"] = NewDNSXLibExecutor(verbose)
		} else {
			tools["dnsx"] = &cliToolExecutor{
				name:         "dnsx",
				binary:       getPathOrDefault("dnsx", cfg.DNSXPath),
				capabilities: []string{"dns"},
				outputFlag:   "-j",
				targetFlag:   "-d",
				defaultArgs:  []string{"-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"},
			}
		}
	}

	if cfg.NaabuEnabled {
		if cfg.PreferLibrary && cfg.NaabuUseLib {
			tools["naabu"] = NewNaabuLibExecutor(verbose)
		} else {
			tools["naabu"] = &cliToolExecutor{
				name:         "naabu",
				binary:       getPathOrDefault("naabu", cfg.NaabuPath),
				capabilities: []string{"portscan"},
				outputFlag:   "-j",
				targetFlag:   "-host",
				defaultArgs:  []string{"-silent"},
			}
		}
	}

	if cfg.HTTPXEnabled {
		if cfg.PreferLibrary && cfg.HTTPXUseLib {
			tools["httpx"] = NewHTTPXLibExecutor(verbose)
		} else {
			tools["httpx"] = &cliToolExecutor{
				name:         "httpx",
				binary:       getPathOrDefault("httpx", cfg.HTTPXPath),
				capabilities: []string{"http", "tech-detect"},
				outputFlag:   "-j",
				targetFlag:   "-u",
				defaultArgs:  []string{"-silent", "-sc", "-title", "-server", "-td", "-ct"},
			}
		}
	}

	if cfg.KatanaEnabled {
		if cfg.PreferLibrary && cfg.KatanaUseLib {
			tools["katana"] = NewKatanaLibExecutor(verbose)
		} else {
			tools["katana"] = &cliToolExecutor{
				name:         "katana",
				binary:       getPathOrDefault("katana", cfg.KatanaPath),
				capabilities: []string{"crawler", "url-discovery"},
				outputFlag:   "-j",
				targetFlag:   "-u",
				defaultArgs:  []string{"-silent"},
			}
		}
	}

	return tools
}

func getPathOrDefault(name, configPath string) string {
	if configPath != "" {
		return configPath
	}
	return name
}
