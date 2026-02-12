package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// =============================================================================
// RECON EXECUTOR
// =============================================================================

// ReconExecutor handles reconnaissance jobs (subdomain, dns, port, http, url discovery).
type ReconExecutor struct {
	mu sync.RWMutex

	// Tool executors
	tools map[string]ToolExecutor

	// Configuration
	config  *ReconConfig
	enabled bool
	verbose bool

	// Pusher for results
	pusher ResultPusher
}

// ReconConfig configures the recon executor.
type ReconConfig struct {
	// Tool-specific enable flags
	SubfinderEnabled bool
	DNSXEnabled      bool
	NaabuEnabled     bool
	HTTPXEnabled     bool
	KatanaEnabled    bool

	// Global settings
	DefaultTimeout int // seconds
	DefaultThreads int
	RateLimit      int // requests per second

	// Tool paths (optional, for custom installations)
	SubfinderPath string
	DNSXPath      string
	NaabuPath     string
	HTTPXPath     string
	KatanaPath    string

	// Hybrid mode - use Go libraries when available (requires -tags hybrid build)
	// When enabled, tools use embedded libraries instead of CLI binaries
	// Benefits: No external dependencies, better error handling, smaller attack surface
	// Trade-offs: Larger binary size, may lag behind CLI versions
	UseHybridMode bool
}

// DefaultReconConfig returns sensible defaults for recon.
func DefaultReconConfig() *ReconConfig {
	return &ReconConfig{
		SubfinderEnabled: true,
		DNSXEnabled:      true,
		NaabuEnabled:     true,
		HTTPXEnabled:     true,
		KatanaEnabled:    true,
		DefaultTimeout:   300, // 5 minutes
		DefaultThreads:   50,
		RateLimit:        150,
	}
}

// NewReconExecutor creates a new recon executor.
func NewReconExecutor(cfg *ReconConfig, pusher ResultPusher, verbose bool) *ReconExecutor {
	if cfg == nil {
		cfg = DefaultReconConfig()
	}

	exec := &ReconExecutor{
		tools:   make(map[string]ToolExecutor),
		config:  cfg,
		enabled: true,
		verbose: verbose,
		pusher:  pusher,
	}

	// Priority: Hybrid > CLI
	// 1. Hybrid mode - uses Go libraries directly (requires -tags hybrid build)
	// 2. CLI wrappers - spawns external CLI processes (default)
	//
	// Note: For direct SDK scanner usage, use the SDK scanners package directly:
	//   import "github.com/openctemio/sdk-go/pkg/scanners/recon/subfinder"
	//   scanner := subfinder.NewScanner()
	//   result, _ := scanner.Scan(ctx, target, opts)
	if cfg.UseHybridMode && HybridModeEnabled {
		hybridCfg := &HybridReconConfig{
			ReconConfig:     cfg,
			PreferLibrary:   true,
			SubfinderUseLib: true,
			DNSXUseLib:      true,
			NaabuUseLib:     false, // Requires libpcap
			HTTPXUseLib:     true,
			KatanaUseLib:    true,
		}
		exec.tools = CreateHybridTools(hybridCfg, verbose)
		if verbose {
			fmt.Printf("[recon] Hybrid mode enabled (library-based executors)\n")
		}
	} else {
		exec.registerTools()
		if verbose && cfg.UseHybridMode && !HybridModeEnabled {
			fmt.Printf("[recon] Warning: Hybrid mode requested but not available (build with -tags hybrid)\n")
		}
	}

	return exec
}

// =============================================================================
// EXECUTOR INTERFACE IMPLEMENTATION
// =============================================================================

func (e *ReconExecutor) Name() string {
	return "recon"
}

func (e *ReconExecutor) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

func (e *ReconExecutor) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

func (e *ReconExecutor) Capabilities() []string {
	caps := []string{"recon"}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, tool := range e.tools {
		caps = append(caps, tool.Capabilities()...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0, len(caps))
	for _, c := range caps {
		if !seen[c] {
			unique = append(unique, c)
			seen[c] = true
		}
	}

	return unique
}

func (e *ReconExecutor) InstalledTools() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var tools []string
	for name, tool := range e.tools {
		if installed, _, _ := tool.IsInstalled(context.Background()); installed {
			tools = append(tools, name)
		}
	}
	return tools
}

// =============================================================================
// JOB EXECUTION
// =============================================================================

func (e *ReconExecutor) Execute(ctx context.Context, job *platform.JobInfo) (*platform.JobResult, error) {
	startTime := time.Now()

	// Parse job payload
	payload, err := e.parsePayload(job)
	if err != nil {
		return e.failResult(job, "invalid payload: "+err.Error(), startTime), err
	}

	// Determine which tool to use
	toolName := payload.Tool
	if toolName == "" {
		toolName = e.inferTool(payload)
	}

	// Get tool executor
	tool, err := e.getTool(toolName)
	if err != nil {
		return e.failResult(job, err.Error(), startTime), err
	}

	// Build tool options
	opts := e.buildOptions(payload)

	// Execute tool
	result, err := tool.Execute(ctx, opts)
	if err != nil {
		return e.failResult(job, "execution failed: "+err.Error(), startTime), err
	}

	// Convert to EIS and push if configured
	if e.pusher != nil && result.Success {
		eisReport, err := e.ProduceCTIS(ctx, job, result)
		if err == nil && eisReport != nil {
			if pushErr := e.pusher.PushCTIS(ctx, eisReport); pushErr != nil {
				// Log but don't fail the job
				if e.verbose {
					fmt.Printf("[recon] Warning: failed to push CTIS report: %v\n", pushErr)
				}
			}
		}
	}

	// Build success result
	return &platform.JobResult{
		JobID:         job.ID,
		Status:        "completed",
		CompletedAt:   time.Now(),
		DurationMs:    time.Since(startTime).Milliseconds(),
		FindingsCount: result.ItemCount,
		Metadata: map[string]any{
			"tool":       toolName,
			"item_count": result.ItemCount,
			"message":    fmt.Sprintf("Recon completed: %d items found", result.ItemCount),
		},
	}, nil
}

// =============================================================================
// CTIS PRODUCTION
// =============================================================================

func (e *ReconExecutor) ProduceCTIS(ctx context.Context, job *platform.JobInfo, result any) (*ctis.Report, error) {
	toolResult, ok := result.(*ToolResult)
	if !ok {
		return nil, fmt.Errorf("expected *ToolResult, got %T", result)
	}

	assets, err := e.ProduceAssets(ctx, toolResult)
	if err != nil {
		return nil, err
	}

	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID:         job.ID,
			Timestamp:  time.Now(),
			SourceType: "recon",
			SourceRef:  job.ID,
		},
		Tool: &ctis.Tool{
			Name:    toolResult.Tool,
			Version: "", // TODO: get tool version
		},
		Assets: assets,
	}

	// Enrich metadata with repo/branch info from payload
	payload, _ := e.parsePayload(job)
	if payload != nil {
		e.enrichReportMetadata(report, payload)
	}

	return report, nil
}

// enrichReportMetadata adds repo/branch info to the report for asset creation.
// This is critical for the ingest service to properly link findings to assets.
func (e *ReconExecutor) enrichReportMetadata(report *ctis.Report, payload *reconPayload) {
	// Add branch info if available (for auto-create asset in ingest)
	if payload.RepoURL != "" || payload.Branch != "" {
		report.Metadata.Branch = &ctis.BranchInfo{
			RepositoryURL:   payload.RepoURL,
			Name:            payload.Branch,
			CommitSHA:       payload.CommitSHA,
			IsDefaultBranch: payload.IsDefault,
		}

		if e.verbose {
			fmt.Printf("[recon] Added branch info to report: repo=%s branch=%s\n", payload.RepoURL, payload.Branch)
		}
	}

	// Add explicit asset if repo URL is provided
	if payload.RepoURL != "" {
		asset := ctis.Asset{
			ID:          "asset-1",
			Type:        ctis.AssetTypeRepository,
			Name:        payload.RepoURL,
			Value:       payload.RepoURL,
			Criticality: ctis.CriticalityHigh,
			Properties: ctis.Properties{
				"branch":            payload.Branch,
				"commit_sha":        payload.CommitSHA,
				"is_default_branch": payload.IsDefault,
			},
		}
		report.Assets = append(report.Assets, asset)

		if e.verbose {
			fmt.Printf("[recon] Added asset to report: %s\n", payload.RepoURL)
		}
	}
}

func (e *ReconExecutor) ProduceAssets(ctx context.Context, output any) ([]ctis.Asset, error) {
	toolResult, ok := output.(*ToolResult)
	if !ok {
		return nil, fmt.Errorf("expected *ToolResult, got %T", output)
	}

	// Parse raw output based on tool type
	switch toolResult.Tool {
	case "subfinder":
		return e.parseSubfinderOutput(toolResult)
	case "dnsx":
		return e.parseDNSXOutput(toolResult)
	case "naabu":
		return e.parseNaabuOutput(toolResult)
	case "httpx":
		return e.parseHTTPXOutput(toolResult)
	case "katana":
		return e.parseKatanaOutput(toolResult)
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolResult.Tool)
	}
}

// =============================================================================
// OUTPUT PARSERS
// =============================================================================

func (e *ReconExecutor) parseSubfinderOutput(result *ToolResult) ([]ctis.Asset, error) {
	if len(result.Output) == 0 {
		return nil, nil
	}

	var assets []ctis.Asset
	lines := strings.Split(string(result.Output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try JSON format first
		var jsonResult struct {
			Host   string `json:"host"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal([]byte(line), &jsonResult); err == nil {
			assets = append(assets, ctis.Asset{
				ID:    fmt.Sprintf("subdomain-%s", jsonResult.Host),
				Type:  ctis.AssetTypeSubdomain,
				Value: jsonResult.Host,
				Name:  jsonResult.Host,
				Properties: map[string]any{
					"source": jsonResult.Source,
				},
			})
			continue
		}

		// Plain text format
		assets = append(assets, ctis.Asset{
			ID:    fmt.Sprintf("subdomain-%s", line),
			Type:  ctis.AssetTypeSubdomain,
			Value: line,
			Name:  line,
		})
	}

	return assets, nil
}

func (e *ReconExecutor) parseDNSXOutput(result *ToolResult) ([]ctis.Asset, error) {
	if len(result.Output) == 0 {
		return nil, nil
	}

	var assets []ctis.Asset
	lines := strings.Split(string(result.Output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var jsonResult struct {
			Host       string   `json:"host"`
			A          []string `json:"a,omitempty"`
			AAAA       []string `json:"aaaa,omitempty"`
			CNAME      []string `json:"cname,omitempty"`
			MX         []string `json:"mx,omitempty"`
			NS         []string `json:"ns,omitempty"`
			TXT        []string `json:"txt,omitempty"`
			StatusCode string   `json:"status_code,omitempty"`
		}

		if err := json.Unmarshal([]byte(line), &jsonResult); err != nil {
			continue
		}

		// Build DNS records
		var dnsRecords []ctis.DNSRecord
		for _, a := range jsonResult.A {
			dnsRecords = append(dnsRecords, ctis.DNSRecord{Type: "A", Name: jsonResult.Host, Value: a})
		}
		for _, aaaa := range jsonResult.AAAA {
			dnsRecords = append(dnsRecords, ctis.DNSRecord{Type: "AAAA", Name: jsonResult.Host, Value: aaaa})
		}
		for _, cname := range jsonResult.CNAME {
			dnsRecords = append(dnsRecords, ctis.DNSRecord{Type: "CNAME", Name: jsonResult.Host, Value: cname})
		}
		for _, mx := range jsonResult.MX {
			dnsRecords = append(dnsRecords, ctis.DNSRecord{Type: "MX", Name: jsonResult.Host, Value: mx})
		}
		for _, ns := range jsonResult.NS {
			dnsRecords = append(dnsRecords, ctis.DNSRecord{Type: "NS", Name: jsonResult.Host, Value: ns})
		}

		asset := ctis.Asset{
			ID:    fmt.Sprintf("domain-%s", jsonResult.Host),
			Type:  ctis.AssetTypeDomain,
			Value: jsonResult.Host,
			Name:  jsonResult.Host,
			Technical: &ctis.AssetTechnical{
				Domain: &ctis.DomainTechnical{
					DNSRecords: dnsRecords,
				},
			},
		}

		assets = append(assets, asset)
	}

	return assets, nil
}

func (e *ReconExecutor) parseNaabuOutput(result *ToolResult) ([]ctis.Asset, error) {
	if len(result.Output) == 0 {
		return nil, nil
	}

	// Group ports by IP
	portsByIP := make(map[string][]ctis.PortInfo)
	lines := strings.Split(string(result.Output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var jsonResult struct {
			IP   string `json:"ip"`
			Host string `json:"host"`
			Port int    `json:"port"`
		}

		if err := json.Unmarshal([]byte(line), &jsonResult); err != nil {
			// Try plain format: host:port
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				var port int
				if _, scanErr := fmt.Sscanf(parts[1], "%d", &port); scanErr == nil {
					ip := parts[0]
					portsByIP[ip] = append(portsByIP[ip], ctis.PortInfo{
						Port:     port,
						Protocol: "tcp",
						State:    "open",
					})
				}
			}
			continue
		}

		ip := jsonResult.IP
		if ip == "" {
			ip = jsonResult.Host
		}

		portsByIP[ip] = append(portsByIP[ip], ctis.PortInfo{
			Port:     jsonResult.Port,
			Protocol: "tcp",
			State:    "open",
		})
	}

	// Convert to assets
	var assets []ctis.Asset
	for ip, ports := range portsByIP {
		assets = append(assets, ctis.Asset{
			ID:    fmt.Sprintf("ip-%s", strings.ReplaceAll(ip, ".", "-")),
			Type:  ctis.AssetTypeIPAddress,
			Value: ip,
			Name:  ip,
			Technical: &ctis.AssetTechnical{
				IPAddress: &ctis.IPAddressTechnical{
					Ports: ports,
				},
			},
		})
	}

	return assets, nil
}

func (e *ReconExecutor) parseHTTPXOutput(result *ToolResult) ([]ctis.Asset, error) {
	if len(result.Output) == 0 {
		return nil, nil
	}

	var assets []ctis.Asset
	lines := strings.Split(string(result.Output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var jsonResult struct {
			URL          string   `json:"url"`
			Input        string   `json:"input"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title"`
			WebServer    string   `json:"webserver"`
			Technologies []string `json:"tech,omitempty"`
			ContentType  string   `json:"content_type"`
			Host         string   `json:"host"`
			Port         string   `json:"port"`
			Scheme       string   `json:"scheme"`
			TLS          bool     `json:"tls"`
		}

		if err := json.Unmarshal([]byte(line), &jsonResult); err != nil {
			continue
		}

		var port int
		_, _ = fmt.Sscanf(jsonResult.Port, "%d", &port)

		asset := ctis.Asset{
			ID:    fmt.Sprintf("http-svc-%s", strings.ReplaceAll(jsonResult.Host, ".", "-")),
			Type:  ctis.AssetTypeHTTPService,
			Value: jsonResult.URL,
			Name:  jsonResult.URL,
			Technical: &ctis.AssetTechnical{
				Service: &ctis.ServiceTechnical{
					Name:     jsonResult.WebServer,
					Port:     port,
					Protocol: jsonResult.Scheme,
					TLS:      jsonResult.TLS,
				},
			},
			Properties: map[string]any{
				"status_code":  jsonResult.StatusCode,
				"title":        jsonResult.Title,
				"content_type": jsonResult.ContentType,
				"technologies": jsonResult.Technologies,
			},
		}

		assets = append(assets, asset)
	}

	return assets, nil
}

func (e *ReconExecutor) parseKatanaOutput(result *ToolResult) ([]ctis.Asset, error) {
	if len(result.Output) == 0 {
		return nil, nil
	}

	var assets []ctis.Asset
	lines := strings.Split(string(result.Output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var jsonResult struct {
			Request struct {
				URL    string `json:"endpoint"`
				Method string `json:"method"`
			} `json:"request"`
			Response struct {
				StatusCode int `json:"status_code"`
			} `json:"response"`
		}

		if err := json.Unmarshal([]byte(line), &jsonResult); err != nil {
			// Plain URL format
			assets = append(assets, ctis.Asset{
				ID:    fmt.Sprintf("url-%d", len(assets)),
				Type:  ctis.AssetTypeDiscoveredURL,
				Value: line,
				Name:  line,
			})
			continue
		}

		assets = append(assets, ctis.Asset{
			ID:    fmt.Sprintf("url-%d", len(assets)),
			Type:  ctis.AssetTypeDiscoveredURL,
			Value: jsonResult.Request.URL,
			Name:  jsonResult.Request.URL,
			Properties: map[string]any{
				"method":      jsonResult.Request.Method,
				"status_code": jsonResult.Response.StatusCode,
			},
		})
	}

	return assets, nil
}

// =============================================================================
// HELPERS
// =============================================================================

type reconPayload struct {
	Tool    string   `json:"tool"`
	Scanner string   `json:"scanner"` // Alias for tool
	Target  string   `json:"target"`
	Targets []string `json:"targets"`
	Options struct {
		Timeout   int      `json:"timeout"`
		Threads   int      `json:"threads"`
		RateLimit int      `json:"rate_limit"`
		ExtraArgs []string `json:"extra_args"`
	} `json:"options"`

	// Repository context for asset creation (optional for recon)
	RepoURL   string `json:"repo_url"`
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
	IsDefault bool   `json:"is_default_branch"`
}

func (e *ReconExecutor) parsePayload(job *platform.JobInfo) (*reconPayload, error) {
	data, err := json.Marshal(job.Payload)
	if err != nil {
		return nil, err
	}

	var payload reconPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	// Handle scanner alias
	if payload.Tool == "" && payload.Scanner != "" {
		payload.Tool = payload.Scanner
	}

	return &payload, nil
}

func (e *ReconExecutor) inferTool(payload *reconPayload) string {
	// Default to subfinder for subdomain discovery
	return "subfinder"
}

func (e *ReconExecutor) getTool(name string) (ToolExecutor, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tool, ok := e.tools[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrToolNotInstalled, name)
	}
	return tool, nil
}

func (e *ReconExecutor) buildOptions(payload *reconPayload) ToolOptions {
	opts := ToolOptions{
		Target:       payload.Target,
		Targets:      payload.Targets,
		OutputFormat: "json",
		Timeout:      e.config.DefaultTimeout,
		Threads:      e.config.DefaultThreads,
		RateLimit:    e.config.RateLimit,
		Verbose:      e.verbose,
	}

	if payload.Options.Timeout > 0 {
		opts.Timeout = payload.Options.Timeout
	}
	if payload.Options.Threads > 0 {
		opts.Threads = payload.Options.Threads
	}
	if payload.Options.RateLimit > 0 {
		opts.RateLimit = payload.Options.RateLimit
	}
	if len(payload.Options.ExtraArgs) > 0 {
		opts.ExtraArgs = payload.Options.ExtraArgs
	}

	return opts
}

func (e *ReconExecutor) failResult(job *platform.JobInfo, message string, startTime time.Time) *platform.JobResult {
	return &platform.JobResult{
		JobID:       job.ID,
		Status:      "failed",
		Error:       message,
		CompletedAt: time.Now(),
		DurationMs:  time.Since(startTime).Milliseconds(),
	}
}

func (e *ReconExecutor) registerTools() {
	if e.config.SubfinderEnabled {
		e.tools["subfinder"] = &cliToolExecutor{
			name:         "subfinder",
			binary:       e.getBinaryPath("subfinder", e.config.SubfinderPath),
			capabilities: []string{"subdomain"},
			outputFlag:   "-oJ",
			targetFlag:   "-d",
			defaultArgs:  []string{"-silent"},
		}
	}

	if e.config.DNSXEnabled {
		e.tools["dnsx"] = &cliToolExecutor{
			name:         "dnsx",
			binary:       e.getBinaryPath("dnsx", e.config.DNSXPath),
			capabilities: []string{"dns"},
			outputFlag:   "-j",
			targetFlag:   "-d",
			defaultArgs:  []string{"-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"},
		}
	}

	if e.config.NaabuEnabled {
		e.tools["naabu"] = &cliToolExecutor{
			name:         "naabu",
			binary:       e.getBinaryPath("naabu", e.config.NaabuPath),
			capabilities: []string{"portscan"},
			outputFlag:   "-j",
			targetFlag:   "-host",
			defaultArgs:  []string{"-silent"},
		}
	}

	if e.config.HTTPXEnabled {
		e.tools["httpx"] = &cliToolExecutor{
			name:         "httpx",
			binary:       e.getBinaryPath("httpx", e.config.HTTPXPath),
			capabilities: []string{"http", "tech-detect"},
			outputFlag:   "-j",
			targetFlag:   "-u",
			defaultArgs:  []string{"-silent", "-sc", "-title", "-server", "-td", "-ct"},
		}
	}

	if e.config.KatanaEnabled {
		e.tools["katana"] = &cliToolExecutor{
			name:         "katana",
			binary:       e.getBinaryPath("katana", e.config.KatanaPath),
			capabilities: []string{"crawler", "url-discovery"},
			outputFlag:   "-j",
			targetFlag:   "-u",
			defaultArgs:  []string{"-silent"},
		}
	}
}

func (e *ReconExecutor) getBinaryPath(name, configPath string) string {
	if configPath != "" {
		return configPath
	}
	return name // Use PATH lookup
}

// =============================================================================
// CLI TOOL EXECUTOR
// =============================================================================

// cliToolExecutor wraps a CLI tool as a ToolExecutor.
type cliToolExecutor struct {
	name         string
	binary       string
	capabilities []string
	outputFlag   string
	targetFlag   string
	defaultArgs  []string
}

func (t *cliToolExecutor) Name() string {
	return t.name
}

func (t *cliToolExecutor) Capabilities() []string {
	return t.capabilities
}

func (t *cliToolExecutor) IsInstalled(ctx context.Context) (bool, string, error) {
	path, err := exec.LookPath(t.binary)
	if err != nil {
		return false, "", nil
	}

	// Try to get version
	cmd := exec.CommandContext(ctx, path, "-version")
	output, _ := cmd.Output()
	version := strings.TrimSpace(string(output))

	return true, version, nil
}

func (t *cliToolExecutor) Execute(ctx context.Context, opts ToolOptions) (*ToolResult, error) {
	startTime := time.Now()

	// Build command arguments
	args := append([]string{}, t.defaultArgs...)

	// Add output format
	if t.outputFlag != "" {
		args = append(args, t.outputFlag)
	}

	// Add target
	if opts.Target != "" {
		args = append(args, t.targetFlag, opts.Target)
	}

	// Add rate limit if supported
	if opts.RateLimit > 0 {
		switch t.name {
		case "subfinder":
			args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
		case "naabu":
			args = append(args, "-rate", fmt.Sprintf("%d", opts.RateLimit))
		case "httpx":
			args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
		case "katana":
			args = append(args, "-rl", fmt.Sprintf("%d", opts.RateLimit))
		}
	}

	// Add threads if supported
	if opts.Threads > 0 {
		switch t.name {
		case "subfinder":
			args = append(args, "-t", fmt.Sprintf("%d", opts.Threads))
		case "naabu":
			args = append(args, "-c", fmt.Sprintf("%d", opts.Threads))
		case "httpx":
			args = append(args, "-t", fmt.Sprintf("%d", opts.Threads))
		case "katana":
			args = append(args, "-c", fmt.Sprintf("%d", opts.Threads))
		}
	}

	// Add extra args
	args = append(args, opts.ExtraArgs...)

	// Create command with timeout
	cmd := exec.CommandContext(ctx, t.binary, args...)

	// Execute
	output, err := cmd.Output()

	result := &ToolResult{
		Tool:      t.name,
		Success:   err == nil,
		Output:    output,
		Duration:  time.Since(startTime).Milliseconds(),
		ItemCount: countLines(output),
	}

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	return result, nil
}

func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	count := 0
	for _, b := range data {
		if b == '\n' {
			count++
		}
	}
	// Add 1 if last line doesn't end with newline
	if len(data) > 0 && data[len(data)-1] != '\n' {
		count++
	}
	return count
}
