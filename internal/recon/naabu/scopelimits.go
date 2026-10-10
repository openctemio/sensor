package naabu

import (
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
)

// WithScopeLimits returns a copy of the scanner whose port list is the
// union of the limited hosts' ports (sdk-go pkg/scopelimit), replacing a
// "top N" or full list. The task's forwarder refuses every other port
// whatever naabu does; the list only keeps naabu from trying them. A job
// whose limits name no port (a protocol or path only) keeps its list.
func (s *Scanner) WithScopeLimits(set scopelimit.Set) (core.ReconScanner, error) {
	var parts []string
	for _, h := range set.Hosts() {
		if p := set.PortList(h); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return s, nil
	}
	c := *s
	c.Ports, c.TopPorts = strings.Join(parts, ","), 0
	return &c, nil
}
