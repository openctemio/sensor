package recon

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/httpx"
)

// HTTPXManifest describes the httpx tool.
var HTTPXManifest = tool.Manifest{
	Name:         "httpx",
	Version:      "1.0.0",
	Description:  "HTTP probe: live web services, titles, servers, technologies, TLS leaf certificates (ProjectDiscovery httpx).",
	Class:        tool.TargetScan,
	Tier:         tool.T1,
	Capabilities: []string{"recon", "http", "tech_detect"},
	Consumes:     []string{"domain", "subdomain", "ip_address", "host", "http_service", "open_port", "service", "website"},
	Produces:     []string{"asset:http_service", "asset:certificate"},
	Permissions:  tool.Permissions{Network: tool.NetTargets},
	Resources: tool.Resources{
		Timeout:        tool.Duration(24 * time.Hour),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1000000,
	},
}

// HTTPXTool runs httpx in the tool child.
var HTTPXTool = portRecon[httpx.Scanner](HTTPXManifest)
