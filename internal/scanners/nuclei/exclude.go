package nuclei

// A job's exclusions (the step's "exclude" setting, core.ScanOptions.
// Exclude) become nuclei -exclude-hosts entries. nuclei applies them twice:
// it drops excluded inputs, and its dialer refuses connections to them, so a
// redirect or a template request to an excluded host is not sent either.
//
// Measured on nuclei v3.11.1: an entry is an IP address, a CIDR range, or a
// host name that nuclei compiles as an unanchored regular expression ("a.b"
// also excludes "aXb", "xa.b"), and an entry that does not compile ("*.b")
// aborts the run. So each exclusion is turned into an exact form here: an
// address or range as is, a host name (or the host of a URL) as an anchored,
// quoted expression, and a wildcard "*.example.com" as "any subdomain of
// example.com". A value that names no host (a path, a glob elsewhere than
// the leftmost label) fails the scan: an exclusion the sensor cannot honour
// exactly must not be dropped silently.

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// maxExcludes bounds the exclusions of one scan.
const maxExcludes = 1000

// hostLabels is a host name: dot-separated labels of letters, digits, '-'
// and '_' (some internal names use it), each 1-63 characters.
var hostLabels = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$`)

// excludeHostArgs returns the -exclude-hosts arguments of a scan's
// exclusions, or an error naming the first value that is not a host, an
// address, a range or a URL.
func excludeHostArgs(values []string) ([]string, error) {
	if len(values) > maxExcludes {
		return nil, fmt.Errorf("too many exclusions: %d (max %d)", len(values), maxExcludes)
	}
	var args []string
	seen := map[string]bool{}
	for _, v := range values {
		e, err := excludeEntry(v)
		if err != nil {
			return nil, err
		}
		if !seen[e] {
			seen[e] = true
			args = append(args, "-exclude-hosts", e)
		}
	}
	return args, nil
}

// excludeEntry is one exclusion as a nuclei -exclude-hosts entry.
func excludeEntry(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	bad := fmt.Errorf("exclusion %q is not a host name, IP address, CIDR range or URL (nuclei excludes hosts)", raw)
	if v == "" || strings.ContainsAny(v, ", \t\r\n") {
		return "", bad
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String(), nil
	}
	if rest, ok := strings.CutPrefix(strings.TrimSuffix(v, "."), "*."); ok {
		if !hostLabels.MatchString(rest) {
			return "", bad
		}
		return `^.+\.` + regexp.QuoteMeta(rest) + `$`, nil
	}
	// A URL, or host[:port]: the host is excluded, whatever the port.
	ref := v
	if !strings.Contains(v, "://") {
		ref = "//" + v
	}
	u, err := url.Parse(ref)
	if err != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/" && !strings.Contains(v, "://")) {
		return "", bad
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		return a.String(), nil
	}
	if !hostLabels.MatchString(host) {
		return "", bad
	}
	return "^" + regexp.QuoteMeta(host) + "$", nil
}

// validateRun checks what a scan's options put on nuclei's command line
// besides its settings: the extra args and the exclusions.
func validateRun(opts *core.ScanOptions) error {
	if opts == nil {
		return nil
	}
	if err := validateExtraArgs(opts.ExtraArgs); err != nil {
		return err
	}
	_, err := excludeHostArgs(opts.Exclude)
	return err
}
