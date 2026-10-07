package recon

import (
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/toolrun"
)

// KatanaManifest describes the katana tool. It crawls the target's own host
// (scope fqdn, no off-host redirects; host-bound extra args are refused)
// and reports the URLs it found.
var KatanaManifest = toolrun.MustManifest(katana.ToolYAML)

// KatanaTool runs katana in the tool child.
var KatanaTool = portRecon[katana.Scanner](KatanaManifest)
