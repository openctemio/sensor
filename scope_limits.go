package main

import (
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sensor/internal/toolrun"
)

// scopeLimitsEnforced reports whether this sensor enforces the port and
// path limits of a job's targets (sdk-go pkg/scopelimit), so it may
// advertise scopelimit.Capability: its tools run out of process, in a
// sandbox that confines their network to the task's forwarder, which
// refuses other ports and reads every request to a path-limited port. A
// sensor without that never advertises it, and the platform keeps
// crawlers, template scanners and top-ports scans off limited targets for
// it.
func scopeLimitsEnforced() bool {
	return toolrun.OutOfProcess() && executor.Current().Status().NetworkEnforced
}
