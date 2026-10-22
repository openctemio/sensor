package recon

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// TakesCapabilityJobs reports whether the recon tool is on the tool
// contract with capabilities (core.CapabilityScanner): the platform may
// send it a capability job (capability, standard params, tier ceiling).
func (s *Scanner) TakesCapabilityJobs() bool {
	p := s.port()
	return p != nil && toolrun.TakesJobs(p.manifest)
}

// EnforcesScopeLimits reports whether a job whose targets carry scope
// limits may run on this tool (core.ScopeLimitScanner): only a tool that
// runs out of process, in the task sandbox whose forwarder enforces them
// (the tool host refuses the task on a sandbox that does not confine the
// network).
func (s *Scanner) EnforcesScopeLimits() bool { return s.port() != nil && toolrun.OutOfProcess() }

var _ core.ScopeLimitScanner = (*Scanner)(nil)

// RoutesEgress reports whether a job's proxy pool carries every connection
// of the tool (core.EgressScanner): a ported tool run out of process,
// behind the task forwarder. A raw-socket scan (naabu SYN), which takes the
// direct path, refuses a pooled job when it starts (outOfProcess).
func (s *Scanner) RoutesEgress() bool { return s.port() != nil && toolrun.OutOfProcess() }
