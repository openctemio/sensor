package naabu

import (
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// DiscoveryPorts are the TCP ports a host discovery job probes when it
// names none: a host that accepts a connection on one of them is live.
const DiscoveryPorts = "80,443,22,3389,8080,8443"

// capabilityHostDiscovery is the capability id naabu runs as host discovery.
const capabilityHostDiscovery = "discover.hosts"

// WithCapability returns the scanner configured for a capability job.
// discover.hosts@1 makes it a host discovery run: a TCP connect probe of a
// few common ports (DiscoveryPorts, unless the job's ports param or the
// scan's settings named others), each address that answers on one of them
// reported live with the port that answered (MarkLive). The tool sandbox
// grants no raw sockets, so ICMP echo is not used. Any other capability
// leaves the scanner as it is.
func (s *Scanner) WithCapability(ref string) (core.ReconScanner, error) {
	id, _, _ := strings.Cut(ref, "@")
	if id != capabilityHostDiscovery {
		return s, nil
	}
	c := *s
	c.HostDiscovery = true
	c.ServiceVersion = false
	if !c.portsSet {
		c.Ports, c.TopPorts, c.PortList = DiscoveryPorts, 0, nil
	}
	return &c, nil
}

// HostDiscoveryMode reports whether the scanner runs as host discovery.
func (s *Scanner) HostDiscoveryMode() bool { return s.HostDiscovery }

// MarkLive turns a port scan report into a host discovery report: every
// address with an answering port is kept as a live ip_address with the
// probe that answered in properties.live_by ("tcp:443"); anything else (a
// host name, an address without an answering port) is dropped, because
// host discovery reports addresses only.
func MarkLive(report *ctis.Report) {
	if report == nil {
		return
	}
	kept := report.Assets[:0]
	for _, a := range report.Assets {
		if a.Type != ctis.AssetTypeIPAddress || a.Technical == nil || a.Technical.IPAddress == nil || len(a.Technical.IPAddress.Ports) == 0 {
			continue
		}
		if a.Properties == nil {
			a.Properties = ctis.Properties{}
		}
		a.Properties["live_by"] = "tcp:" + strconv.Itoa(a.Technical.IPAddress.Ports[0].Port)
		kept = append(kept, a)
	}
	report.Assets = kept
}
