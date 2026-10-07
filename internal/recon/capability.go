package recon

import "github.com/openctemio/sensor/internal/toolrun"

// TakesCapabilityJobs reports whether the recon tool is on the tool
// contract with capabilities (core.CapabilityScanner): the platform may
// send it a capability job (capability, standard params, tier ceiling).
func (s *Scanner) TakesCapabilityJobs() bool {
	p := s.port()
	return p != nil && toolrun.TakesJobs(p.manifest)
}
