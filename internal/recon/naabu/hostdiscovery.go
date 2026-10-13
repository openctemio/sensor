package naabu

import (
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// WithCapability returns the scanner configured for a capability job.
// discover.hosts@1 makes it a host discovery run: a TCP connect probe of the
// ports the platform named in the job (its ports param), each address that
// answers on one of them reported live (core.LiveHostsReport). The platform
// decides the probe set; a job without one is refused, never probed with a
// set the sensor picks. The tool sandbox grants no raw sockets, so ICMP
// echo is not used. Any other capability leaves the scanner as it is.
func (s *Scanner) WithCapability(ref string) (core.ReconScanner, error) {
	id, _, _ := strings.Cut(ref, "@")
	if id != core.CapabilityHostDiscovery {
		return s, nil
	}
	if !s.portsSet || (s.Ports == "" && s.TopPorts == 0) {
		return nil, core.ErrNoProbePorts
	}
	c := *s
	c.HostDiscovery = true
	c.ServiceVersion = false
	return &c, nil
}

// HostDiscoveryMode reports whether the scanner runs as host discovery.
func (s *Scanner) HostDiscoveryMode() bool { return s.HostDiscovery }
