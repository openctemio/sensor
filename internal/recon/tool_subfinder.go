package recon

import (
	"github.com/openctemio/sdk-go/pkg/core"

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

// credentialTool is a recon tool that takes the task's source keys: the
// credentials its manifest declares, by name, written into the task
// directory dir. log receives what the tool reports of each source.
type credentialTool interface {
	core.ReconScanner
	WithCredentials(dir string, keys map[string]string, log func(msg string, args ...any)) (core.ReconScanner, error)
}

var _ credentialTool = (*subfinder.Scanner)(nil)
