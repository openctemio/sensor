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

// netConfined reports whether this sensor may advertise
// executor.CapabilityNetConfined: its tools run out of process, in a
// sandbox whose network is confined to each task's forwarder. The platform
// sends jobs that need confinement (a web scope, scope limits) only to a
// sensor that advertises it, and keeps them waiting for one otherwise.
// It comes from the runtime's status, never from a setting.
func netConfined() bool {
	return toolrun.OutOfProcess() && executor.Current().Status().NetworkEnforced
}

// httpIdentityApplied reports whether this sensor may advertise
// toolhost.CapabilityHTTPIdentity: its tools run out of process, through
// the tool host, which sends the job's User-Agent and headers (a
// bug-bounty program's required identification) on every request. The
// platform holds jobs that carry such identification from a sensor that
// does not advertise it. It comes from how tools run, never from a setting.
func httpIdentityApplied() bool {
	return toolrun.OutOfProcess()
}
