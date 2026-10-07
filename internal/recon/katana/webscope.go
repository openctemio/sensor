package katana

// The job's web scope (sdk-go pkg/webscope) on a katana crawl. katana
// makes its own requests, so the scope becomes its flags:
//
//   - deny paths: an out-of-scope regex (-cos) per path, matching it in
//     any case and with any character percent-encoded, as servers decode
//     them; katana resolves dot segments before it checks the scope;
//   - path prefixes and hosts: an in-scope regex (-cs); the field scope
//     stays fqdn, so the crawl never leaves the target's host whatever the
//     hosts allow (the narrower of the two applies);
//   - methods: katana crawls with GET; form filling, which submits forms,
//     is off unless the scope allows POST.
//
// Redirects stay off (-dr). The results are filtered again with the scope
// (webscope.Scope.Allows), so a URL katana reported outside it never
// reaches the platform.

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// WithWebScope returns a copy of the scanner that keeps to the scope. An
// invalid scope is an error, never ignored.
func (s *Scanner) WithWebScope(ws *webscope.Scope) (core.ReconScanner, error) {
	if ws == nil {
		return s, nil
	}
	if err := ws.Validate(); err != nil {
		return nil, err
	}
	c := *s
	c.WebScope = ws
	c.FollowRedirects = false
	if c.Scope == "" || c.FieldScope != "" {
		c.Scope, c.FieldScope = ScopeFQDN, ""
	}
	if !slices.Contains(ws.Methods, "POST") {
		c.FormFill = false
	}
	return &c, nil
}

// scopeArgs are the katana flags of the web scope (none without one).
func (s *Scanner) scopeArgs() []string {
	ws := s.WebScope
	if ws == nil {
		return nil
	}
	var args []string
	for _, d := range ws.DenyPaths {
		args = append(args, "-cos", `^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+`+pathRegex(d))
	}
	var hostRE string
	if len(ws.Hosts) > 0 {
		alts := make([]string, 0, len(ws.Hosts))
		for _, h := range ws.Hosts {
			if apex, ok := strings.CutPrefix(strings.ToLower(h), "*."); ok {
				alts = append(alts, `([^/?#@]*\.)?`+regexp.QuoteMeta(apex))
			} else {
				alts = append(alts, regexp.QuoteMeta(strings.ToLower(h)))
			}
		}
		hostRE = `(?i)^https?://(` + strings.Join(alts, "|") + `)\.?(:[0-9]+)?`
	}
	if len(ws.PathPrefixes) > 0 {
		alts := make([]string, 0, len(ws.PathPrefixes))
		for _, p := range ws.PathPrefixes {
			p = strings.TrimSuffix(p, "/")
			alts = append(alts, regexp.QuoteMeta(p)+`([/?#]|$)`)
		}
		if hostRE == "" {
			hostRE = `^https?://[^/]+`
		}
		args = append(args, "-cs", hostRE+`(`+strings.Join(alts, "|")+`)`)
	} else if hostRE != "" {
		args = append(args, "-cs", hostRE+`([/?#]|$)`)
	}
	return args
}

// pathRegex matches a path prefix in any case, each character literal or
// percent-encoded, and a slash also as a run of slashes or a backslash.
func pathRegex(p string) string {
	var b strings.Builder
	b.WriteString("(?i)")
	for _, r := range p {
		switch {
		case r == '/':
			b.WriteString(`(/|\\|%2f|%5c)+`)
		case unicode.IsLetter(r) && r < 0x80:
			lo, up := unicode.ToLower(r), unicode.ToUpper(r)
			fmt.Fprintf(&b, `(%c|%%%02x|%%%02x)`, lo, lo, up)
		case r < 0x80:
			fmt.Fprintf(&b, `(%s|%%%02x)`, regexp.QuoteMeta(string(r)), r)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

// inWebScope keeps the URLs the scope allows (all without a scope). The
// target's host is the scope's host when it names none.
func (s *Scanner) inWebScope(target string, urls []core.DiscoveredURL) []core.DiscoveredURL {
	if s.WebScope == nil {
		return urls
	}
	hosts := []string{urlHost(target)}
	kept := urls[:0]
	for _, u := range urls {
		p, err := url.Parse(u.URL)
		if err != nil {
			continue
		}
		m := u.Method
		if m == "" {
			m = "GET"
		}
		if s.WebScope.Allows(m, p, hosts) == nil {
			kept = append(kept, u)
		}
	}
	return kept
}
