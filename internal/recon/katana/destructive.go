package katana

// Every crawl keeps away from links that name a state-changing action
// (contract webpath.Destructive: a logout link, "/admin/delete?id=1",
// "resetPassword"): a GET may still trigger one. katana gets an out-of-scope
// regex (-cos) built from webpath.DestructiveVerbs, so it never requests
// such a link, and the results are filtered again with webpath.Destructive,
// so none reaches the platform. The regex over-blocks (a verb anywhere in
// the path or query, any case, any letter percent-encoded); the filter is
// exact.

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/openctemio/contract/webpath"
	"github.com/openctemio/sdk-go/pkg/core"
)

// exactVerbs are the verbs webpath matches only as a whole word ("drop",
// not "dropdown").
var exactVerbs = []string{"drop", "kill", "wipe"}

// joinedVerbs are verbs a link may spell as two words ("log-out",
// "sign_out").
var joinedVerbs = [][2]string{{"log", "out"}, {"log", "off"}, {"sign", "out"}}

// destructiveRegex is the -cos regex of every crawl.
var destructiveRegex = buildDestructiveRegex()

func buildDestructiveRegex() string {
	var alts []string
	for _, v := range webpath.DestructiveVerbs {
		if slices.Contains(exactVerbs, v) {
			continue
		}
		alts = append(alts, encodedWord(v))
	}
	for _, j := range joinedVerbs {
		alts = append(alts, encodedWord(j[0])+`[^a-z0-9]?`+encodedWord(j[1]))
	}
	exact := make([]string, 0, len(exactVerbs))
	for _, v := range exactVerbs {
		exact = append(exact, encodedWord(v))
	}
	e := strings.Join(exact, "|")
	// The path (and query) of the URL: after the host, from its first "/"
	// or "?" (a host never holds either, so a host name is never matched).
	const path = `^[a-z][a-z0-9+.-]*://[^/?#]+[/?]`
	return `(?i:` + path + `.*(` + strings.Join(alts, "|") + `))` +
		// A whole word: bounded by anything that is not a letter or digit (a
		// percent escape included)...
		`|(?i:` + path + `(.*[^a-z0-9])?(` + e + `)([^a-z0-9]|$))` +
		// ...or followed by an upper-case letter ("dropUser"; case-sensitive).
		`|(?i:` + path + `.*)(drop|kill|wipe|Drop|Kill|Wipe)[A-Z]`
}

// encodedWord matches a lower-case ASCII word with each letter literal or
// percent-encoded (in any case, under the regex's (?i)).
func encodedWord(w string) string {
	var b strings.Builder
	for _, r := range w {
		fmt.Fprintf(&b, `(%c|%%%02x)`, r, r)
	}
	return b.String()
}

// destructiveArgs are the katana flags of the destructive-link filter.
func destructiveArgs() []string { return []string{"-cos", destructiveRegex} }

// withoutDestructive drops the URLs whose path or query names a
// state-changing action.
func withoutDestructive(urls []core.DiscoveredURL) []core.DiscoveredURL {
	kept := urls[:0]
	for _, u := range urls {
		if isDestructiveURL(u.URL) {
			continue
		}
		kept = append(kept, u)
	}
	return kept
}

func isDestructiveURL(raw string) bool {
	p, err := url.Parse(raw)
	if err != nil {
		return true // unreadable: not kept
	}
	s := p.EscapedPath()
	if p.RawQuery != "" {
		s += "?" + p.RawQuery
	}
	return webpath.Destructive(s)
}
