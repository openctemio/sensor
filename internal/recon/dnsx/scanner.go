// Package dnsx provides a scanner implementation for the dnsx DNS toolkit.
package dnsx

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
	// DefaultBinary is the default dnsx binary name.
	DefaultBinary = "dnsx"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 15 * time.Minute

	// DefaultThreads is the default concurrency level.
	DefaultThreads = 100

	// DefaultRetries is the default number of retries.
	DefaultRetries = 2
)

// Scanner implements the ReconScanner interface for dnsx.
type Scanner struct {
	// Configuration
	Binary  string        // Path to dnsx binary (default: "dnsx")
	Timeout time.Duration // Scan timeout (default: 15 minutes)
	Verbose bool          // Enable verbose output

	// Scan options
	Threads   int      // Number of concurrent threads
	RateLimit int      // Rate limit (queries per second)
	Retries   int      // Number of retries
	Resolvers []string // Custom DNS resolvers

	// Query options
	RecordTypes     []string // DNS record types to query (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, CAA)
	QueryAll        bool     // Query all record types
	ResponseOnly    bool     // Output only response values
	RespectWildcard bool     // Filter hosts that resolve only through a wildcard zone (-auto-wildcard)

	// Output options
	OutputFile string // Output file path
	Silent     bool   // Silent mode
	OutputJSON bool   // JSON output

	// Filters
	OutputCDN    bool // Output CDN info
	OutputASN    bool // Output ASN info
	OutputHostIP bool // Output host:ip pairs

	// Internal
	version string
}

// NewScanner creates a new dnsx scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:      DefaultBinary,
		Timeout:     DefaultTimeout,
		Threads:     DefaultThreads,
		Retries:     DefaultRetries,
		RecordTypes: []string{"A", "AAAA", "CNAME"},
		OutputJSON:  true,
	}
}

// NewARecordScanner creates a scanner for A/AAAA records only.
func NewARecordScanner() *Scanner {
	s := NewScanner()
	s.RecordTypes = []string{"A", "AAAA"}
	return s
}

// NewFullRecordScanner creates a scanner for all DNS record types.
func NewFullRecordScanner() *Scanner {
	s := NewScanner()
	s.QueryAll = true
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "dnsx"
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Type returns the recon type.
func (s *Scanner) Type() core.ReconType {
	return core.ReconTypeDNS
}

// IsInstalled checks if dnsx is installed.
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

// parseVersion extracts version from dnsx output.
func parseVersion(output string) string {
	// Current releases print "[INF] Current Version: vX.Y.Z" to stderr.
	if v := core.VersionAfterLabel(output, "Current Version:"); v != "" {
		return v
	}
	// dnsx version output: "dnsx v1.x.x"
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "dnsx") {
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

// Scan performs DNS resolution on the target hosts.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ReconOptions) (*core.ReconResult, error) {
	start := time.Now()

	// Build dnsx arguments
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	args := s.buildArgs(target, opts)

	if s.Verbose {
		fmt.Printf("[dnsx] Target: %s\n", target)
		fmt.Printf("[dnsx] Args: %v\n", args)
	}

	// Execute dnsx
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
	dnsRecords, err := s.parseOutput(execResult.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dnsx output: %w", err)
	}

	// Hosts the first run left unresolved: once more through the system
	// resolver (see fallback.go).
	if fb, fbOpts, cleanup, ok := s.fallbackPlan(target, opts, execResult.Stdout); ok {
		fbArgs := fb.buildArgs("", fbOpts)
		if s.Verbose {
			fmt.Printf("[dnsx] System-resolver fallback: %v\n", fbArgs)
		}
		fbResult, fbErr := core.ExecuteScanner(ctx, &core.ExecConfig{
			Binary:  binary,
			Args:    fbArgs,
			Timeout: timeout,
			Verbose: s.Verbose,
		})
		cleanup()
		if fbErr == nil {
			if more, perr := s.parseOutput(fbResult.Stdout); perr == nil {
				dnsRecords = append(dnsRecords, more...)
				execResult.Stdout = append(append([]byte{}, execResult.Stdout...), fbResult.Stdout...)
			}
		} else if s.Verbose {
			fmt.Printf("[dnsx] System-resolver fallback failed: %v\n", fbErr)
		}
	}

	result := &core.ReconResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		ReconType:      s.Type(),
		Target:         target,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		DNSRecords:     dnsRecords,
		RawOutput:      execResult.Stdout,
		ExitCode:       execResult.ExitCode,
	}

	// A run that resolved none of its hosts failed: before, it completed
	// with 0 records, which the platform read as "these names have no
	// records" (research/22c B5, a silent false negative). The reason names
	// the resolvers, so a broken resolver is told apart from names that do
	// not exist.
	if execResult.ExitCode == 0 {
		if inputs, known := inputHosts(target, opts); known && len(inputs) > 0 && len(answeredHosts(execResult.Stdout)) == 0 {
			result.Error = fmt.Sprintf("dnsx resolved none of the %d host(s) through %s (NXDOMAIN, no answer, or the resolvers are unreachable)", len(inputs), resolverLabel(s.resolvers(opts)))
		}
	}

	if s.Verbose {
		fmt.Printf("[dnsx] Found %d DNS records in %dms\n", len(dnsRecords), result.DurationMs)
	}

	return result, nil
}

// buildArgs builds the dnsx command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ReconOptions) []string {
	args := []string{}

	// Input specification
	if opts != nil && opts.InputFile != "" {
		args = append(args, "-l", opts.InputFile)
	} else if target != "" {
		// -l takes a file or a comma-separated host list. -d is dnsx's
		// brute-force domain input: it requires a wordlist (-w) and exits
		// with "missing wordlist" without one.
		args = append(args, "-l", target)
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

	// Retries
	if s.Retries > 0 {
		args = append(args, "-retry", fmt.Sprintf("%d", s.Retries))
	}

	// Resolvers
	resolvers := s.Resolvers
	if opts != nil && len(opts.Resolvers) > 0 {
		resolvers = opts.Resolvers
	}
	if len(resolvers) > 0 {
		args = append(args, "-r", strings.Join(resolvers, ","))
	}

	// Record types
	if s.QueryAll {
		args = append(args, "-recon")
	} else if len(s.RecordTypes) > 0 {
		for _, rt := range s.RecordTypes {
			args = append(args, "-"+strings.ToLower(rt))
		}
	}

	// Response options
	if s.ResponseOnly {
		args = append(args, "-resp-only")
	}
	if s.RespectWildcard {
		// dnsx has no -rw; -auto-wildcard detects wildcard zones and drops
		// the hosts that only resolve because of them.
		args = append(args, "-auto-wildcard")
	}

	// Output enrichment
	if s.OutputCDN {
		args = append(args, "-cdn")
	}
	if s.OutputASN {
		args = append(args, "-asn")
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

// DNSXOutput represents the JSON output from dnsx.
type DNSXOutput struct {
	Host       string   `json:"host"`
	Resolver   []string `json:"resolver,omitempty"`
	A          []string `json:"a,omitempty"`
	AAAA       []string `json:"aaaa,omitempty"`
	CNAME      []string `json:"cname,omitempty"`
	MX         []string `json:"mx,omitempty"`
	NS         []string `json:"ns,omitempty"`
	TXT        []string `json:"txt,omitempty"`
	SOA        *SOA     `json:"soa,omitempty"`
	PTR        []string `json:"ptr,omitempty"`
	CAA        []string `json:"caa,omitempty"`
	StatusCode string   `json:"status_code,omitempty"`
	CDN        bool     `json:"cdn,omitempty"`
	CDNName    string   `json:"cdn_name,omitempty"`
	ASN        *ASN     `json:"asn,omitempty"`
}

// SOA represents SOA record data.
type SOA struct {
	Name    string `json:"name"`
	NS      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minttl  uint32 `json:"minttl"`
}

// ASN represents ASN information.
type ASN struct {
	AsNumber  string   `json:"as_number"`
	AsName    string   `json:"as_name"`
	AsCountry string   `json:"as_country"`
	AsRange   []string `json:"as_range"`
}

// parseOutput parses dnsx JSON output.
func (s *Scanner) parseOutput(data []byte) ([]core.DNSRecord, error) {
	var records []core.DNSRecord

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var output DNSXOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If not JSON, skip
			continue
		}

		// Convert to DNSRecord format
		resolver := ""
		if len(output.Resolver) > 0 {
			resolver = output.Resolver[0]
		}

		// A records
		if len(output.A) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "A",
				Values:     output.A,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// AAAA records
		if len(output.AAAA) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "AAAA",
				Values:     output.AAAA,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// CNAME records
		if len(output.CNAME) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "CNAME",
				Values:     output.CNAME,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// MX records
		if len(output.MX) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "MX",
				Values:     output.MX,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// NS records
		if len(output.NS) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "NS",
				Values:     output.NS,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// TXT records
		if len(output.TXT) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "TXT",
				Values:     output.TXT,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// SOA record
		if output.SOA != nil {
			soaValue := fmt.Sprintf("%s %s %d %d %d %d %d",
				output.SOA.NS, output.SOA.Mbox,
				output.SOA.Serial, output.SOA.Refresh,
				output.SOA.Retry, output.SOA.Expire, output.SOA.Minttl)
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "SOA",
				Values:     []string{soaValue},
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// PTR records
		if len(output.PTR) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "PTR",
				Values:     output.PTR,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}

		// CAA records
		if len(output.CAA) > 0 {
			records = append(records, core.DNSRecord{
				Host:       output.Host,
				RecordType: "CAA",
				Values:     output.CAA,
				Resolver:   resolver,
				StatusCode: output.StatusCode,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// GetIPsForHosts performs DNS resolution and returns host:IP mappings.
func (s *Scanner) GetIPsForHosts(ctx context.Context, hosts []string, opts *core.ReconOptions) (map[string][]string, error) {
	// Write hosts to temp file
	tmpFile, err := writeTempFile(hosts)
	if err != nil {
		return nil, err
	}
	defer removeTempFile(tmpFile)

	// Set up options
	if opts == nil {
		opts = &core.ReconOptions{}
	}
	opts.InputFile = tmpFile

	// Run scan
	result, err := s.Scan(ctx, "", opts)
	if err != nil {
		return nil, err
	}

	// Build mapping
	hostToIPs := make(map[string][]string)
	for _, record := range result.DNSRecords {
		if record.RecordType == "A" || record.RecordType == "AAAA" {
			hostToIPs[record.Host] = append(hostToIPs[record.Host], record.Values...)
		}
	}

	return hostToIPs, nil
}

// writeTempFile writes hosts to a temporary file.
func writeTempFile(hosts []string) (string, error) {
	tmpFile, err := createTempFile("dnsx-input-*.txt")
	if err != nil {
		return "", err
	}

	for _, host := range hosts {
		if _, err := tmpFile.WriteString(host + "\n"); err != nil {
			_ = tmpFile.Close()
			return "", err
		}
	}

	_ = tmpFile.Close()
	return tmpFile.Name(), nil
}

// resolverLabel names a run's resolvers for an error message.
func resolverLabel(resolvers []string) string {
	if len(resolvers) == 0 {
		return "dnsx's built-in public resolvers"
	}
	return "resolvers " + strings.Join(resolvers, ",")
}

// Limits returns the scanner's own request rate and concurrency (0: none
// set, unlimited). A scan may only lower them (recon.Scanner).
func (s *Scanner) Limits() (rate, concurrency int) {
	return s.RateLimit, s.Threads
}
