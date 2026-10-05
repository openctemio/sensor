package recon

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/dnsx"
)

// DNSXManifest describes the dnsx tool. dnsx only queries DNS, through the
// sensor's resolvers (SENSOR_DNS_RESOLVERS or /etc/resolv.conf, read by the
// sensor and handed to the child); it never connects to the target hosts.
// Its records are reported on domain assets.
var DNSXManifest = tool.Manifest{
	Name:         "dnsx",
	Version:      "1.0.0",
	Description:  "DNS resolution of domains and subdomains through the sensor's resolvers (ProjectDiscovery dnsx).",
	Class:        tool.TargetScan,
	Tier:         tool.T0,
	Capabilities: []string{"recon", "dns"},
	Consumes:     []string{"domain", "subdomain", "host"},
	Produces:     []string{"asset:domain"},
	Permissions:  tool.Permissions{Network: tool.NetTargets},
	Resources: tool.Resources{
		Timeout:        tool.Duration(24 * time.Hour),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1000000,
	},
}

// DNSXTool runs dnsx in the tool child.
var DNSXTool = portRecon[dnsx.Scanner](DNSXManifest)
