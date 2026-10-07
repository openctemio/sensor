package recon

import (
	"github.com/openctemio/sensor/internal/recon/subfinder"
	"github.com/openctemio/sensor/internal/toolrun"
)

// SubfinderManifest describes the subfinder tool. subfinder is passive: it
// never contacts the target, it asks public sources (certificate
// transparency logs, passive DNS, search APIs) through the sensor's egress.
// It produces the root domain and the subdomains it found (with their
// resolved addresses as DNS records).
var SubfinderManifest = toolrun.MustManifest(subfinder.ToolYAML)

// SubfinderTool runs subfinder in the tool child.
var SubfinderTool = portRecon[subfinder.Scanner](SubfinderManifest)
