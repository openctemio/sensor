package recon

import (
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/toolrun"
)

// HTTPXManifest describes the httpx tool.
var HTTPXManifest = toolrun.MustManifest(httpx.ToolYAML)

// HTTPXTool runs httpx in the tool child.
var HTTPXTool = portRecon[httpx.Scanner](HTTPXManifest)
