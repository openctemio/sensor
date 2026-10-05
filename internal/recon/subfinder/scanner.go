// Package subfinder provides a scanner implementation for the subfinder subdomain enumeration tool.
package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBinary is the default subfinder binary name.
	DefaultBinary = "subfinder"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute

	// DefaultThreads is the default concurrency level.
	DefaultThreads = 30

	// DefaultRateLimit is the default rate limit.
	DefaultRateLimit = 0 // No rate limit by default
)

// Scanner implements the ReconScanner interface for subfinder.
type Scanner struct {
	// Configuration
	Binary  string        // Path to subfinder binary (default: "subfinder")
	Timeout time.Duration // Scan timeout (default: 30 minutes)
	Verbose bool          // Enable verbose output

	// Scan options
	Threads   int      // Number of concurrent threads
	RateLimit int      // Rate limit (queries per second)
	Resolvers []string // Custom DNS resolvers

	// Source options
	Sources        []string // Specific sources to use
	ExcludeSources []string // Sources to exclude
	All            bool     // Use all sources (slower but comprehensive)
	Recursive      bool     // Enable recursive subdomain enumeration

	// Output options
	OutputFile string // Output file path (empty = stdout)
	Silent     bool   // Silent mode - only output subdomains

	// Proxy
	Proxy string // HTTP proxy URL

	// Internal
	version string
}

// NewScanner creates a new subfinder scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:  DefaultBinary,
		Timeout: DefaultTimeout,
		Threads: DefaultThreads,
	}
}

// NewPassiveScanner creates a scanner for passive-only enumeration (faster).
func NewPassiveScanner() *Scanner {
	s := NewScanner()
	s.Sources = []string{"crtsh", "hackertarget", "threatcrowd", "urlscan", "waybackarchive"}
	return s
}

// NewAggressiveScanner creates a scanner using all sources (slower but comprehensive).
func NewAggressiveScanner() *Scanner {
	s := NewScanner()
	s.All = true
	s.Recursive = true
	s.Threads = 50
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "subfinder"
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Type returns the recon type.
func (s *Scanner) Type() core.ReconType {
	return core.ReconTypeSubdomain
}

// IsInstalled checks if subfinder is installed.
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

// parseVersion extracts version from subfinder output.
func parseVersion(output string) string {
	// Current releases print "[INF] Current Version: vX.Y.Z" to stderr.
	if v := core.VersionAfterLabel(output, "Current Version:"); v != "" {
		return v
	}
	// subfinder version output: "subfinder v2.x.x"
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "subfinder") {
		parts := strings.Fields(output)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return output
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// Scan performs subdomain enumeration on the target domain.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ReconOptions) (*core.ReconResult, error) {
	start := time.Now()

	// Build subfinder arguments
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	args := s.buildArgs(target, opts)

	if s.Verbose {
		fmt.Printf("[subfinder] Target: %s\n", target)
		fmt.Printf("[subfinder] Args: %v\n", args)
	}

	// Execute subfinder
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
	subdomains, err := s.parseOutput(execResult.Stdout, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subfinder output: %w", err)
	}

	result := &core.ReconResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		ReconType:      s.Type(),
		Target:         target,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		Subdomains:     subdomains,
		RawOutput:      execResult.Stdout,
		ExitCode:       execResult.ExitCode,
	}

	if s.Verbose {
		fmt.Printf("[subfinder] Found %d subdomains in %dms\n", len(subdomains), result.DurationMs)
	}

	return result, nil
}

// buildArgs builds the subfinder command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ReconOptions) []string {
	args := []string{}

	// Target specification
	if opts != nil && opts.InputFile != "" {
		args = append(args, "-dL", opts.InputFile)
	} else if target != "" {
		args = append(args, "-d", target)
	}

	// No update check: it calls ProjectDiscovery's servers on every run.
	args = append(args, "-duc")

	// Output format - JSON for structured parsing
	args = append(args, "-oJ")

	// Concurrency
	threads := s.Threads
	if opts != nil && opts.Threads > 0 {
		threads = opts.Threads
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}

	// Rate limit
	rateLimit := s.RateLimit
	if opts != nil && opts.RateLimit > 0 {
		rateLimit = opts.RateLimit
	}
	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	// Resolvers
	resolvers := s.Resolvers
	if opts != nil && len(opts.Resolvers) > 0 {
		resolvers = opts.Resolvers
	}
	if len(resolvers) > 0 {
		args = append(args, "-r", strings.Join(resolvers, ","))
	}

	// Sources
	if len(s.Sources) > 0 {
		args = append(args, "-sources", strings.Join(s.Sources, ","))
	}
	if len(s.ExcludeSources) > 0 {
		args = append(args, "-es", strings.Join(s.ExcludeSources, ","))
	}

	// All sources
	if s.All {
		args = append(args, "-all")
	}

	// Recursive
	if s.Recursive {
		args = append(args, "-recursive")
	}

	// Output file
	if s.OutputFile != "" {
		args = append(args, "-o", s.OutputFile)
	}

	// Silent mode
	if s.Silent || !s.Verbose {
		args = append(args, "-silent")
	}

	// Proxy
	if s.Proxy != "" {
		args = append(args, "-proxy", s.Proxy)
	}

	// Extra args from options
	if opts != nil && len(opts.ExtraArgs) > 0 {
		args = append(args, opts.ExtraArgs...)
	}

	return args
}

// SubfinderOutput represents the JSON output from subfinder.
type SubfinderOutput struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// parseOutput parses subfinder JSON output.
func (s *Scanner) parseOutput(data []byte, rootDomain string) ([]core.Subdomain, error) {
	var subdomains []core.Subdomain
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var output SubfinderOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If not JSON, treat as plain subdomain
			host := line
			if !seen[host] {
				seen[host] = true
				subdomains = append(subdomains, core.Subdomain{
					Host:   host,
					Domain: rootDomain,
				})
			}
			continue
		}

		// Deduplicate
		if seen[output.Host] {
			continue
		}
		seen[output.Host] = true

		subdomains = append(subdomains, core.Subdomain{
			Host:   output.Host,
			Domain: output.Input,
			Source: output.Source,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

// ScanToFile performs scan and saves results to a file.
func (s *Scanner) ScanToFile(ctx context.Context, target string, outputFile string, opts *core.ReconOptions) (*core.ReconResult, error) {
	s.OutputFile = outputFile

	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	// Read output file if scan was successful
	if result.ExitCode == 0 && outputFile != "" {
		data, readErr := os.ReadFile(outputFile)
		if readErr == nil {
			result.RawOutput = data
		}
	}

	return result, nil
}

// GetSubdomainsOnly performs scan and returns only the subdomain list.
func (s *Scanner) GetSubdomainsOnly(ctx context.Context, target string, opts *core.ReconOptions) ([]string, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for _, sub := range result.Subdomains {
		hosts = append(hosts, sub.Host)
	}

	return hosts, nil
}

// Limits returns the scanner's own request rate and concurrency (0: none
// set, unlimited). A scan may only lower them (recon.Scanner).
func (s *Scanner) Limits() (rate, concurrency int) {
	return s.RateLimit, s.Threads
}
