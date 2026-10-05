package toolrun

import (
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Every task of a ported tool is admitted by the runtime before its child
// starts (sdk-go toolhost.Admit): the tool's manifest permissions
// intersected with the sensor-local policy in force and the mode the sensor
// runs in. A target the policy refuses is removed from the task (the child
// never sees it) and reported skipped with class refused_by_policy; a task
// with no target left is refused.

var mode tool.Mode

// SetAdmission sets the policy every task is admitted against and the mode
// the sensor runs in (daemon, or runner for a CI run). The policy is asked
// at each task, so a reload of the local policy applies to the next task.
// A nil policy admits by the manifest alone.
func SetAdmission(p toolhost.Policy, m tool.Mode) {
	mu.Lock()
	defer mu.Unlock()
	h := *host
	h.Policy = p
	host = &h
	mode = m
}

// current returns the host and the run options with the sensor's mode.
func current(o toolhost.RunOptions) (*toolhost.Host, toolhost.RunOptions) {
	mu.RLock()
	defer mu.RUnlock()
	if o.Mode == "" {
		o.Mode = mode
	}
	return host, o
}

// Refused returns the targets the admission refused (skipped with class
// refused_by_policy), for the caller to report.
func Refused(out *toolhost.Outcome) []toolhost.TargetOutcome {
	if out == nil {
		return nil
	}
	var r []toolhost.TargetOutcome
	for _, t := range out.Targets {
		if t.Class == tool.RefusedByPolicy {
			r = append(r, t)
		}
	}
	return r
}
