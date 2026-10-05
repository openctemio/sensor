package recon

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/subfinder"
)

// SubfinderManifest describes the subfinder tool. subfinder is passive: it
// never contacts the target, it asks public sources (certificate
// transparency logs, passive DNS, search APIs) through the sensor's egress.
// It produces the root domain and the subdomains it found (with their
// resolved addresses as DNS records).
var SubfinderManifest = tool.Manifest{
	Name:         "subfinder",
	Version:      "1.0.0",
	Description:  "Passive subdomain enumeration from public sources (ProjectDiscovery subfinder); never contacts the target.",
	Class:        tool.TargetScan,
	Tier:         tool.T0,
	Capabilities: []string{"recon", "subdomain"},
	Consumes:     []string{"domain"},
	Produces:     []string{"asset:domain", "asset:subdomain"},
	Permissions:  tool.Permissions{Network: tool.NetEgressProxy},
	Resources: tool.Resources{
		Timeout:        tool.Duration(24 * time.Hour),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1000000,
	},
}

// SubfinderTool runs subfinder in the tool child.
var SubfinderTool = portRecon[subfinder.Scanner](SubfinderManifest)
