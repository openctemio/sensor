package recon

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/toolrun"
)

// DNSXEnumManifest describes the dnsx brute-force tool (enumerate.subdomains).
// It is active (T1) and reads the label list the platform names in the
// signed job; it has no list of its own.
var DNSXEnumManifest = toolrun.MustManifest(dnsx.EnumToolYAML)

// DNSXEnumTool runs the brute force in the tool child.
var DNSXEnumTool = portRecon[dnsx.EnumScanner](DNSXEnumManifest)

// wordlistTool is a recon tool that reads one wordlist slot of the job.
type wordlistTool interface {
	core.ReconScanner
	// WordlistSlot is the content slot the list comes in.
	WordlistSlot() string
	// WithWordlist returns the tool configured to read the list at path.
	WithWordlist(path string) (core.ReconScanner, error)
}

// The brute force reads the job's list and keeps to its excluded hosts.
var (
	_ wordlistTool     = (*dnsx.EnumScanner)(nil)
	_ excludeHostsTool = (*dnsx.EnumScanner)(nil)
)
