package recon

import (
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/toolrun"
)

// DNSXManifest describes the dnsx tool. dnsx only queries DNS, through the
// sensor's resolvers (SENSOR_DNS_RESOLVERS or /etc/resolv.conf, read by the
// sensor and handed to the child); it never connects to the target hosts.
// Its records are reported on domain assets.
var DNSXManifest = toolrun.MustManifest(dnsx.ToolYAML)

// DNSXTool runs dnsx in the tool child.
var DNSXTool = portRecon[dnsx.Scanner](DNSXManifest)
