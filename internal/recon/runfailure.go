package recon

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/reachobs"
)

// runFailure is a failure of a whole tool run: the process exited with an
// error before it reported anything for the target list (naabu printing a
// fatal line and exiting 1). It is a fact about this run on this sensor,
// never about each target: reading its text as every target's reach outcome
// ("operation not permitted" as a firewall in front of every address, "no
// valid ipv4 or ipv6 targets" as every name not resolving) failed a whole
// host discovery step as TARGET_UNREACHABLE while the targets were never
// probed. The failure names the cause on the sensor's side instead.
type runFailure struct {
	err   error
	class core.FailureClass
	cause string
}

func (e *runFailure) Error() string {
	if e.cause == "" {
		return e.err.Error()
	}
	return e.cause + " (" + e.err.Error() + ")"
}

func (e *runFailure) Unwrap() error { return e.err }

// FailureClass names the sensor-side class (core.ClassifyFailure reads it).
func (e *runFailure) FailureClass() (class, reason string) { return string(e.class), "" }

// Causes a whole-run failure is named with.
const (
	causeLocalRefused = "the sensor's host refused the tool's network calls (operation not permitted): " +
		"a local firewall rule, the container's seccomp profile or capabilities, or the sandbox; " +
		"this is about the sensor, not the targets"
	causeSensorDNS = "the sensor could not resolve the job's names: its DNS resolver did not answer " +
		"(for a container, the engine's resolver); this is about the sensor, not the targets"
	causeNoAddress = "the tool found no address it could scan in the job's list " +
		"(every address excluded, or none valid for it); no target was probed"
	causeNoRoute = "the sensor has no network route (its interface or default route is down); " +
		"this is about the sensor, not the targets"
)

// classifyRun names the cause of a whole-run failure of a tool given
// targets.
func classifyRun(err error, targets []string) *runFailure {
	rf := &runFailure{err: err, class: core.FailureUnknown}
	msg := err.Error()
	switch reachobs.Classify(msg) {
	case reach.FirewallRefused:
		rf.class, rf.cause = core.FailureSensorNetwork, causeLocalRefused
	case reach.NoRoute:
		rf.class, rf.cause = core.FailureSensorNetwork, causeNoRoute
	case reach.DNSFailure:
		if hasName(targets) {
			rf.class, rf.cause = core.FailureDNSResolver, causeSensorDNS
		} else {
			// Only addresses and ranges: nothing needed DNS. The tool had
			// nothing it could probe.
			rf.cause = causeNoAddress
		}
	}
	return rf
}

// hasName reports whether targets hold a host name (not an address or a
// range).
func hasName(targets []string) bool {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, err := netip.ParseAddr(t); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(t); err == nil {
			continue
		}
		if lo, hi, ok := strings.Cut(t, "-"); ok {
			if _, e1 := netip.ParseAddr(lo); e1 == nil {
				if _, e2 := netip.ParseAddr(hi); e2 == nil {
					continue
				}
			}
		}
		return true
	}
	return false
}

// runFailureError is the tool error a failed recon run ends the task with:
// a sensor network or DNS failure is temporary for the platform (another
// sensor, or this one later, may run it), with the cause in its detail;
// anything else is the tool's failure.
func runFailureError(err error) error {
	var rf *runFailure
	if errors.As(err, &rf) {
		switch rf.class {
		case core.FailureDNSResolver, core.FailureSensorNetwork:
			return &tool.Error{Class: tool.Transient, Retryable: true, Detail: err.Error()}
		}
	}
	return tool.Failed(err)
}
