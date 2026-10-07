package recon

import (
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/toolrun"
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
var NaabuManifest = toolrun.MustManifest(naabu.ToolYAML)

// NaabuTool runs naabu in the tool child.
var NaabuTool = portRecon[naabu.Scanner](NaabuManifest)
