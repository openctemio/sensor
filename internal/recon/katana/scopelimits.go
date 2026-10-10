package katana

import (
	"slices"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// WithScopeLimits returns a copy of the scanner that crawls only under the
// path prefixes of the limited hosts (sdk-go pkg/scopelimit), as a web
// scope (webscope.go). The task's forwarder refuses every request outside
// them whatever katana does; the scope keeps katana from trying. A job
// whose web scope already names prefixes keeps them (the forwarder applies
// the limits on top).
func (s *Scanner) WithScopeLimits(set scopelimit.Set) (core.ReconScanner, error) {
	var prefixes []string
	for _, h := range set.Hosts() {
		for _, l := range set.Limits(h) {
			if l.PathPrefix != "" && !slices.Contains(prefixes, l.PathPrefix) {
				prefixes = append(prefixes, l.PathPrefix)
			}
		}
	}
	if len(prefixes) == 0 || (s.WebScope != nil && len(s.WebScope.PathPrefixes) > 0) {
		return s, nil
	}
	ws := webscope.Scope{}
	if s.WebScope != nil {
		ws = *s.WebScope
	}
	ws.PathPrefixes = prefixes
	return s.WithWebScope(&ws)
}
