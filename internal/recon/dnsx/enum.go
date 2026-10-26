package dnsx

// Subdomain brute force with dnsx (capability enumerate.subdomains@1).
//
// The tool is dnsx's own brute-force mode: `dnsx -d <root> -w <labels>`
// queries <label>.<root> for each label of the list and prints the names
// that resolve. It is a separate tool (dnsx-enum, tier T1) from the T0
// resolver so a passive job never needs the tier of an active one.
//
// The label list is never the tool's own and never chosen here: the platform
// names it in the signed job (content slot "labels", purpose dns-labels) and
// the runtime composes it into one file in the task directory. A job without
// a list is refused, so brute force is opt-in by depth: only a job the
// platform planned for a depth that allows it carries one.
//
// Threat model: the root is the job's target, already admitted against the
// job's scope and the sensor's local policy. Every query is <label>.<root>
// (a label is checked as a DNS label by the runtime), so no name outside the
// root is ever queried, and every name reported is checked to lie under the
// root and outside the job's excluded hosts. Queries are rate limited (50 per
// second unless a scan lowers it; the cap is 500) and bounded by max_queries.
// Names that do not resolve are never reported, and a wildcard zone is
// filtered by dnsx (-auto-wildcard).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// EnumName is the tool's name.
const EnumName = "dnsx-enum"

const (
	// EnumDefaultRate is the default queries per second of a brute force.
	EnumDefaultRate = 50
	// EnumDefaultThreads is the default concurrency of a brute force.
	EnumDefaultThreads = 50
	// EnumTimeout bounds one root's brute force.
	EnumTimeout = 6 * time.Hour
	// maxLabelBytes bounds the list read when it is cut at max_queries.
	maxLabelBytes = 64 << 20
)

// ErrNoWordlist is returned when a brute force has no label list: the
// sensor has no list of its own.
var ErrNoWordlist = errors.New("dnsx-enum: the job carries no label list (content slot \"labels\"); the sensor has no built-in list")

// EnumScanner is dnsx's brute-force mode. It embeds the resolver's options
// (threads, retries, timeout, wildcard filter, resolvers).
type EnumScanner struct {
	Scanner
	// Wordlist is the composed label list in the task directory, set by the
	// tool host's content (WithWordlist), never from a job's free text.
	Wordlist string `json:"wordlist,omitempty"`
	// MaxQueries cuts the list (0: all of it).
	MaxQueries int `json:"max_queries,omitempty"`
	// Exclude are hosts the job excludes: a name equal to or below one is
	// not reported.
	Exclude []string `json:"exclude,omitempty"`
}

// NewEnumScanner returns the brute-force tool with its defaults.
func NewEnumScanner() *EnumScanner {
	s := NewScanner()
	s.RecordTypes = []string{"A", "AAAA", "CNAME"}
	s.RateLimit = EnumDefaultRate
	s.Threads = EnumDefaultThreads
	s.Timeout = EnumTimeout
	return &EnumScanner{Scanner: *s}
}

// Name returns the tool name.
func (s *EnumScanner) Name() string { return EnumName }

// SettingsSchema returns the tool's settings schema.
func (s *EnumScanner) SettingsSchema() *core.SettingsSchema { return enumSettingsSchema }

// WordlistSlot is the content slot the label list comes in.
func (s *EnumScanner) WordlistSlot() string { return "labels" }

// WithWordlist returns a copy that reads the label list at path.
func (s *EnumScanner) WithWordlist(path string) (core.ReconScanner, error) {
	if path == "" {
		return nil, ErrNoWordlist
	}
	c := *s
	c.Wordlist = path
	return &c, nil
}

// WithExcludeHosts returns a copy that drops names at or below the hosts.
func (s *EnumScanner) WithExcludeHosts(hosts []string) (core.ReconScanner, error) {
	c := *s
	c.Exclude = nil
	for _, h := range hosts {
		if h = normalizeHost(h); h != "" {
			c.Exclude = append(c.Exclude, h)
		}
	}
	return &c, nil
}

// WithSettings returns a copy configured with a scan's settings.
func (s *EnumScanner) WithSettings(ts *core.ToolSettings) (core.ReconScanner, error) {
	if ts == nil {
		return s, nil
	}
	if ts.SchemaDigest() != enumSettingsSchema.Digest() {
		return nil, fmt.Errorf("dnsx-enum settings: resolved against schema %q, not %q", ts.SchemaDigest(), enumSettingsSchema.Digest())
	}
	c := *s
	if v, ok := ts.Int("rate_limit"); ok {
		c.RateLimit = int(v)
	}
	if v, ok := ts.Int("threads"); ok {
		c.Threads = int(v)
	}
	if v, ok := ts.Int("timeout"); ok {
		c.RequestTimeout = int(v)
	}
	if v, ok := ts.Int("retries"); ok {
		c.Retries = int(v) + 1
	}
	if v, ok := ts.Int("max_queries"); ok {
		c.MaxQueries = int(v)
	}
	return &c, nil
}

// enumSettingsSchema is the config schema of the tool's descriptor.
var enumSettingsSchema = core.MustParseSettingsSchema(string(toolrun.MustManifest(EnumToolYAML).Config))

// Scan brute-forces the subdomains of the root target.
func (s *EnumScanner) Scan(ctx context.Context, target string, opts *core.ReconOptions) (*core.ReconResult, error) {
	start := time.Now()
	root, err := enumRoot(target)
	if err != nil {
		return nil, err
	}
	if s.Wordlist == "" {
		return nil, ErrNoWordlist
	}
	if opts != nil {
		if err := core.ValidateExtraArgs(opts.ExtraArgs); err != nil {
			return nil, err
		}
	}
	list := s.Wordlist
	if s.MaxQueries > 0 {
		cut, cleanup, err := cutList(s.Wordlist, s.MaxQueries)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		list = cut
	}
	// The root and list are the only inputs: a file of targets has no place
	// in a brute force.
	var scan core.ReconOptions
	if opts != nil {
		scan = *opts
	}
	scan.InputFile = ""
	args := append([]string{"-d", root, "-w", list}, s.Scanner.buildArgs("", &scan)...)
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}
	timeout := s.Timeout
	if opts != nil && opts.Timeout > 0 {
		timeout = opts.Timeout
	}
	if s.Verbose {
		fmt.Printf("[dnsx-enum] Root: %s Args: %v\n", root, args)
	}
	res, err := core.ExecuteScanner(ctx, &core.ExecConfig{Binary: binary, Args: args, Timeout: timeout, Verbose: s.Verbose})
	out := &core.ReconResult{
		ScannerName: s.Name(), ScannerVersion: s.version, ReconType: s.Type(), Target: target,
		StartedAt: start.Unix(),
	}
	if err != nil {
		out.FinishedAt, out.DurationMs, out.ExitCode, out.Error = time.Now().Unix(), time.Since(start).Milliseconds(), -1, err.Error()
		return out, nil
	}
	records, err := s.parseOutput(res.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dnsx output: %w", err)
	}
	out.DNSRecords = keepUnder(records, root, s.Exclude)
	out.RawOutput, out.ExitCode = res.Stdout, res.ExitCode
	out.FinishedAt, out.DurationMs = time.Now().Unix(), time.Since(start).Milliseconds()
	// No error when nothing resolved: a root can have no names under the
	// list, and that is the answer.
	return out, nil
}

// enumRoot checks the target is one domain name (not an address, URL or
// list) and returns it normalised.
func enumRoot(target string) (string, error) {
	root := normalizeHost(target)
	if root == "" || strings.ContainsAny(root, ",/:@ \t\r\n*") || net.ParseIP(root) != nil || !strings.Contains(root, ".") {
		return "", fmt.Errorf("dnsx-enum: %q is not a root domain", target)
	}
	for _, l := range strings.Split(root, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("dnsx-enum: %q is not a root domain", target)
		}
	}
	return root, nil
}

// keepUnder keeps the records of names strictly below root and not at or
// below an excluded host, the only names a brute force of root may report.
func keepUnder(records []core.DNSRecord, root string, exclude []string) []core.DNSRecord {
	out := records[:0:0]
	for _, r := range records {
		h := normalizeHost(r.Host)
		if !strings.HasSuffix(h, "."+root) || excluded(h, exclude) {
			continue
		}
		r.Host = h
		out = append(out, r)
	}
	return out
}

func excluded(host string, exclude []string) bool {
	for _, e := range exclude {
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

// cutList writes the first n lines of the list to a temporary file.
func cutList(path string, n int) (string, func(), error) {
	in, err := os.Open(path) //nolint:gosec // the composed list in the task directory
	if err != nil {
		return "", nil, fmt.Errorf("dnsx-enum: open the label list: %w", err)
	}
	defer func() { _ = in.Close() }()
	f, err := createTempFile("dnsx-enum-labels-*.txt")
	if err != nil {
		return "", nil, fmt.Errorf("dnsx-enum: %w", err)
	}
	cleanup := func() { removeTempFile(f.Name()) }
	w := bufio.NewWriter(f)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	read, lines := 0, 0
	for sc.Scan() && lines < n {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if read += len(line) + 1; read > maxLabelBytes {
			break
		}
		_, _ = w.WriteString(line + "\n")
		lines++
	}
	if err := errors.Join(sc.Err(), w.Flush(), f.Close()); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("dnsx-enum: cut the label list: %w", err)
	}
	return f.Name(), cleanup, nil
}
