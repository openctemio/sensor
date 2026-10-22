package semgrep

import "github.com/openctemio/sensor/internal/toolrun"

// TakesCapabilityJobs reports whether the tool runs capability jobs
// (core.CapabilityScanner): its descriptor implements capabilities.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(ToolManifest) }

// RoutesEgress reports whether a job's proxy pool carries every connection
// of the tool (core.EgressScanner): the tool runs out of process, behind
// the task forwarder; the in-process path would go direct, so a pooled job
// is refused there.
func (s *Scanner) RoutesEgress() bool { return toolrun.OutOfProcess() }
