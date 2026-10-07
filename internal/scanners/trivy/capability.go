package trivy

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// CapabilitySBOM is the capability whose job builds the component
// inventory only (ctis/capability sbom.generate@1).
const CapabilitySBOM = "sbom.generate@1"

// forCapability is the scanner configured for the job's capability (a copy
// when it changes anything). An sbom.generate@1 job lists every package
// and matches no vulnerability, misconfiguration or secret: trivy runs its
// license scanner only, which needs no vulnerability database.
func (s *Scanner) forCapability(opts *core.ScanOptions) *Scanner {
	if opts == nil || opts.Capability != CapabilitySBOM {
		return s
	}
	c := *s
	c.Scanners = []string{"license"}
	c.ListAllPkgs = true
	c.MisconfigScanners = nil
	return &c
}

// TakesCapabilityJobs reports whether the tool runs capability jobs
// (core.CapabilityScanner): its descriptor implements capabilities.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(ToolManifest) }
