package recon

import (
	"encoding/json"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/naabu"
)

// NaabuManifest describes the naabu tool. Out of process it runs as a TCP
// connect scan only: the tool sandbox grants no Linux capabilities, so the
// manifest declares none (a SYN scan, which needs raw sockets, stays on the
// direct path). It resolves names through the sensor's resolvers and
// reports each host (an IP address or a host name) with its open ports in
// the asset's technical details (the converter's default: no separate
// open_port assets). The
// configuration schema is the one scans are validated against; settings
// are applied by the sensor before the child starts.
var NaabuManifest = tool.Manifest{
	Name:         "naabu",
	Version:      "1.0.0",
	Description:  "TCP connect port scan of the target's hosts (ProjectDiscovery naabu); no raw sockets, no capabilities.",
	Class:        tool.TargetScan,
	Tier:         tool.T1,
	Capabilities: []string{"recon", "portscan"},
	Consumes:     []string{"domain", "subdomain", "ip_address", "host"},
	Produces:     []string{"asset:ip_address", "asset:host"},
	Config:       json.RawMessage(naabu.SettingsSchemaJSON()),
	Permissions:  tool.Permissions{Network: tool.NetTargets},
	Resources: tool.Resources{
		Timeout:        tool.Duration(24 * time.Hour),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1000000,
	},
}

// NaabuTool runs naabu in the tool child.
var NaabuTool = portRecon[naabu.Scanner](NaabuManifest)
