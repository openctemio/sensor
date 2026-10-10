package nuclei

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// TakesCapabilityJobs reports whether the tool runs capability jobs
// (core.CapabilityScanner): its descriptor implements capabilities.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(ToolManifest) }

// EnforcesScopeLimits reports whether a job whose targets carry scope
// limits may run (core.ScopeLimitScanner): nuclei runs out of process, in
// the task sandbox whose forwarder enforces them.
func (s *Scanner) EnforcesScopeLimits() bool { return toolrun.OutOfProcess() }

var _ core.ScopeLimitScanner = (*Scanner)(nil)
