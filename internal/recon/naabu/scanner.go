// Package naabu provides a scanner implementation for the naabu port scanning tool.
package naabu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"

	"github.com/openctemio/sensor/internal/egressenv"
)

const (
	// DefaultBinary is the default naabu binary name.
	DefaultBinary = "naabu"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute

	// DefaultRate is the default packets per second.
	DefaultRate = 1000

	// DefaultRetries is the default number of retries.
	DefaultRetries = 3
)

// ScanType represents the type of port scan.
type ScanType string

const (
	ScanTypeSYN     ScanType = "s" // SYN scan (default, requires root)
	ScanTypeConnect ScanType = "c" // Connect scan (no root required)
)

// Scanner implements the ReconScanner interface for naabu.
type Scanner struct {
	// Configuration
	Binary  string        // Path to naabu binary (default: "naabu")
	Timeout time.Duration // Scan timeout (default: 30 minutes)
	Verbose bool          // Enable verbose output

	// Scan options
	Rate     int      // Packets per second
	Retries  int      // Number of retries
	ScanType ScanType // Scan type (SYN or Connect)

	// Port configuration
	Ports        string // Ports to scan: "80,443", "1-1000", "top-100", "top-1000", "full"
	TopPorts     int    // Top N ports to scan
	ExcludePorts string // Ports to exclude
	PortList     []int  // Explicit port list

	// Network options
	Interface string   // Network interface to use
	SourceIP  string   // Source IP address
	Resolvers []string // Custom DNS resolvers

	// Host discovery
	SkipHostDiscovery bool // Skip host discovery
	Ping              bool // Use ICMP ping

	// Output options
	OutputFile string // Output file path
	OutputJSON bool   // JSON output
	Silent     bool   // Silent mode

	// Service detection
	ServiceVersion bool // Probe for service versions

	// Internal
	version string
	// scanRate is a scan's requested packet rate (settings "rate"): it only
	// lowers the rate the sensor runs with, never raises it.
	scanRate int
	// retriesSet: Retries came from a scan's settings, so it is passed even
	// when 0.
	retriesSet bool
}

// NewScanner creates a new naabu scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:     DefaultBinary,
		Timeout:    DefaultTimeout,
		Rate:       DefaultRate,
		Retries:    DefaultRetries,
		ScanType:   ScanTypeConnect, // Default to connect scan (no root required)
		Ports:      "top-100",
		OutputJSON: true,
	}
}

// NewTop100Scanner creates a scanner for top 100 ports.
func NewTop100Scanner() *Scanner {
	s := NewScanner()
	s.Ports = "top-100"
	return s
}

// NewTop1000Scanner creates a scanner for top 1000 ports.
func NewTop1000Scanner() *Scanner {
	s := NewScanner()
	s.Ports = "top-1000"
	return s
}

// NewFullScanner creates a scanner for all 65535 ports.
func NewFullScanner() *Scanner {
	s := NewScanner()
	s.Ports = "1-65535"
	s.Rate = 5000 // Higher rate for full scan
	return s
}

// NewWebScanner creates a scanner for common web ports.
func NewWebScanner() *Scanner {
	s := NewScanner()
	s.Ports = "80,443,8080,8443,8000,8888,9000,9443"
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "naabu"
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Type returns the recon type.
func (s *Scanner) Type() core.ReconType {
	return core.ReconTypePort
}

// IsInstalled checks if naabu is installed.
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

// parseVersion extracts version from naabu output.
func parseVersion(output string) string {
	// Current releases print "[INF] Current Version: vX.Y.Z" to stderr.
	if v := core.VersionAfterLabel(output, "Current Version:"); v != "" {
		return v
	}
	// naabu version output: "naabu v2.x.x"
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "naabu") {
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

// Scan performs port scanning on the target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ReconOptions) (*core.ReconResult, error) {
	start := time.Now()

	// Build naabu arguments
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	args := s.buildArgs(target, opts)

	if s.Verbose {
		fmt.Printf("[naabu] Target: %s\n", target)
		fmt.Printf("[naabu] Args: %v\n", args)
	}

	// Execute naabu
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
	openPorts, err := s.parseOutput(execResult.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse naabu output: %w", err)
	}

	result := &core.ReconResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		ReconType:      s.Type(),
		Target:         target,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		OpenPorts:      openPorts,
		RawOutput:      execResult.Stdout,
		ExitCode:       execResult.ExitCode,
	}

	if s.Verbose {
		fmt.Printf("[naabu] Found %d open ports in %dms\n", len(openPorts), result.DurationMs)
	}

	return result, nil
}

// buildArgs builds the naabu command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ReconOptions) []string {
	args := []string{}

	// Input specification
	if opts != nil && opts.InputFile != "" {
		args = append(args, "-l", opts.InputFile)
	} else if target != "" {
		args = append(args, "-host", target)
	}

	// No update check: it calls ProjectDiscovery's servers on every run.
	args = append(args, "-duc")

	// Output format - JSON for structured parsing
	if s.OutputJSON {
		args = append(args, "-json")
	}

	// Port configuration
	if s.Ports != "" {
		switch s.Ports {
		case "top-100":
			args = append(args, "-top-ports", "100")
		case "top-1000":
			args = append(args, "-top-ports", "1000")
		case "full", "1-65535":
			args = append(args, "-p", "-")
		default:
			args = append(args, "-p", s.Ports)
		}
	}
	if s.TopPorts > 0 {
		args = append(args, "-top-ports", fmt.Sprintf("%d", s.TopPorts))
	}
	if s.ExcludePorts != "" {
		args = append(args, "-exclude-ports", s.ExcludePorts)
	}

	// Rate limiting
	rate := s.Rate
	if opts != nil && opts.RateLimit > 0 {
		rate = opts.RateLimit
	}
	// A scan may ask for a lower rate, never a higher one: the sensor's rate
	// (naabu's default when the sensor sets none) is the ceiling.
	if s.scanRate > 0 {
		ceiling := rate
		if ceiling <= 0 {
			ceiling = DefaultRate
		}
		rate = min(s.scanRate, ceiling)
	}
	if rate > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", rate))
	}

	// Retries
	if s.Retries > 0 || s.retriesSet {
		args = append(args, "-retries", fmt.Sprintf("%d", s.Retries))
	}

	// Scan type
	if s.ScanType != "" {
		// -s (-scan-type) takes the type as its value. A bare "-c" is
		// naabu's worker-count flag: it swallowed the next argument and
		// every scan failed with `invalid value "-silent" for flag -c`.
		args = append(args, "-s", string(s.ScanType))
	}

	// Network options
	if s.Interface != "" {
		args = append(args, "-interface", s.Interface)
	}
	if s.SourceIP != "" {
		args = append(args, "-source-ip", s.SourceIP)
	}

	// A confined task connects through its forwarder's relay (SOCKS5;
	// naabu runs a connect scan).
	if a := egressenv.SOCKSAddr(); a != "" {
		args = append(args, "-proxy", a)
	}

	// Resolvers
	resolvers := s.Resolvers
	if opts != nil && len(opts.Resolvers) > 0 {
		resolvers = opts.Resolvers
	}
	// A confined task reaches no resolver but its forwarder's relay.
	if r := egressenv.Resolver(); r != "" {
		resolvers = []string{r}
	}
	if len(resolvers) > 0 {
		args = append(args, "-r", strings.Join(resolvers, ","))
	}
	// Fall back to the host's resolver (/etc/resolv.conf). Otherwise naabu
	// resolves host names only through its built-in public resolvers, so a
	// name that only the sensor's network knows (an internal zone, a Docker
	// or Kubernetes service name) failed with "no valid ipv4 or ipv6
	// targets were found" while httpx and nuclei reached the same host.
	args = append(args, "-sr")

	// Host discovery
	if s.SkipHostDiscovery {
		args = append(args, "-Pn")
	}
	if s.Ping {
		args = append(args, "-ping")
	}

	// Service version detection
	if s.ServiceVersion {
		args = append(args, "-sV") // flags are case-sensitive; -sv is not defined
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

// NaabuOutput represents the JSON output from naabu.
type NaabuOutput struct {
	Host      string `json:"host"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol,omitempty"`
	TLS       bool   `json:"tls,omitempty"`
	CDN       bool   `json:"cdn,omitempty"`
	CDNName   string `json:"cdn-name,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// parseOutput parses naabu JSON output.
func (s *Scanner) parseOutput(data []byte) ([]core.OpenPort, error) {
	var openPorts []core.OpenPort
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var output NaabuOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If not JSON, try to parse as "host:port" format
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host := parts[0]
				port, err := strconv.Atoi(parts[1])
				if err == nil {
					key := fmt.Sprintf("%s:%d", host, port)
					if !seen[key] {
						seen[key] = true
						openPorts = append(openPorts, core.OpenPort{
							Host:     host,
							Port:     port,
							Protocol: "tcp",
						})
					}
				}
			}
			continue
		}

		// Deduplicate
		key := fmt.Sprintf("%s:%d", output.Host, output.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		protocol := output.Protocol
		if protocol == "" {
			protocol = "tcp"
		}

		openPorts = append(openPorts, core.OpenPort{
			Host:     output.Host,
			IP:       output.IP,
			Port:     output.Port,
			Protocol: protocol,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return openPorts, nil
}

// GetOpenPorts performs scan and returns only the port list.
func (s *Scanner) GetOpenPorts(ctx context.Context, target string, opts *core.ReconOptions) ([]int, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	var ports []int
	seen := make(map[int]bool)
	for _, p := range result.OpenPorts {
		if !seen[p.Port] {
			seen[p.Port] = true
			ports = append(ports, p.Port)
		}
	}

	return ports, nil
}

// GetHostPortPairs performs scan and returns host:port pairs.
func (s *Scanner) GetHostPortPairs(ctx context.Context, target string, opts *core.ReconOptions) ([]string, error) {
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	var pairs []string
	for _, p := range result.OpenPorts {
		pairs = append(pairs, fmt.Sprintf("%s:%d", p.Host, p.Port))
	}

	return pairs, nil
}

// Limits returns the scanner's own request rate and concurrency (0: none
// set, unlimited). A scan may only lower them (recon.Scanner).
func (s *Scanner) Limits() (rate, concurrency int) {
	return s.Rate, 0
}
