package betterleaks

import "github.com/openctemio/sensor/internal/toolrun"

// TakesCapabilityJobs reports whether the tool runs capability jobs
// (core.CapabilityScanner): its descriptor implements capabilities.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(ToolManifest) }
