package recon

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/katana"
)

// KatanaManifest describes the katana tool. It crawls the target's own host
// (scope fqdn, no off-host redirects; host-bound extra args are refused)
// and reports the URLs it found.
var KatanaManifest = tool.Manifest{
	Name:         "katana",
	Version:      "1.0.0",
	Description:  "Web crawler for URL and endpoint discovery on the target's host (ProjectDiscovery katana).",
	Class:        tool.TargetScan,
	Tier:         tool.T1,
	Capabilities: []string{"recon", "crawler", "url_discovery"},
	Consumes:     []string{"domain", "subdomain", "host", "http_service", "website", "web_application"},
	Produces:     []string{"asset:discovered_url"},
	Permissions:  tool.Permissions{Network: tool.NetTargets},
	Resources: tool.Resources{
		Timeout:        tool.Duration(24 * time.Hour),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1000000,
	},
}

// KatanaTool runs katana in the tool child.
var KatanaTool = portRecon[katana.Scanner](KatanaManifest)
