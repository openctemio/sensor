package executor

import (
	"context"
	"os"

	"github.com/openctemio/sdk-go/pkg/core"
)

// The scan-target guard lives in the sdk-go core (core.ScanTargetPolicy with
// ByScanner): every scan command's targets are checked there, one by one,
// right before the tool starts. A refused target is removed from the job and
// reported (refused_targets, outcome skipped/refused); the job runs on the
// rest and fails only when every target is refused. This file wires the
// sensor's settings into it.
//
// Threat model: a tenant admin (or a compromised platform) names an asset
// whose target is attacker-controlled. Without the guard the sensor hands
// http://169.254.169.254 to nuclei and the response (cloud credentials)
// lands in a finding, or hands ~/.ssh to a code scanner.
//
// Blocked always: loopback, link-local (cloud metadata), CGNAT, multicast,
// reserved, and their names (localhost, metadata.google.internal). Blocked by
// default: RFC1918 and ULA, opened by SENSOR_ALLOW_PRIVATE_TARGETS=1 for
// on-prem sensors scanning their own network. A name that does not resolve
// is refused (fail closed). Only http and https URLs.

// allowPrivateTargets is toggled from the SENSOR_ALLOW_PRIVATE_TARGETS
// env var at init-time. Tests override this variable directly to
// exercise both modes.
var allowPrivateTargets = privateTargetsFromEnv(os.LookupEnv)

// privateTargetsFromEnv reads SENSOR_ALLOW_PRIVATE_TARGETS, the one switch
// for private scan targets. Removed names (AGENT_ALLOW_PRIVATE_TARGETS, ...)
// never widen it; main refuses to start while one is set.
func privateTargetsFromEnv(lookup func(string) (string, bool)) bool {
	v, _ := lookup(core.EnvSensorAllowPrivateTargets)
	return v == "1"
}

// ScanTargetPolicy is the policy the SDK executor checks every scan target
// against: each target by the scanner that receives it, code-scanner paths
// confined to the scan workspace (none configured: paths are refused).
func ScanTargetPolicy(ws *Workspace) *core.ScanTargetPolicy {
	p := core.DefaultScanTargetPolicy()
	p.AllowPrivate = allowPrivateTargets
	p.AllowLoopback = false
	p.ByScanner = true
	p.AllowedRoots = ws.Roots()
	if len(p.AllowedRoots) == 0 {
		// No workspace: no directory a path could be confined to.
		p.AllowedRoots = []string{noScanRoot}
	}
	return p
}

// noScanRoot is a root no path resolves into: with no scan workspace every
// filesystem target is refused.
const noScanRoot = "/nonexistent/filesystem-scan-targets-disabled"

// validateScannerTarget checks a target a network tool (a validation probe,
// a retest) connects to, with the same network guard as scans. Empty input
// passes: callers decide whether an empty target means anything.
func validateScannerTarget(target string) error {
	if target == "" {
		return nil
	}
	return ScanTargetPolicy(nil).ValidateNetworkTarget(context.Background(), target)
}
