package main

// Which mode the sensor runs in, decided from the command line alone (no
// I/O), so the matrix is unit-tested. The daemon with platform commands is
// the default: a minimal start needs only the platform URL and a pairing
// code or key. A one-shot run is what a command line naming a tool, a
// target or an output asks for.

import (
	"flag"
	"fmt"
)

// oneShotFlags ask for one run and exit when given (without -daemon).
var oneShotFlags = []string{"tool", "target", "push", "json", "output"}

// deprecatedIgnoredMsg explains the leftover capability flags.
const deprecatedIgnoredMsg = "capabilities follow the installed tools; narrow with the local policy's tools.allow"

// resolveDaemonMode reports whether to run the daemon, and the warnings the
// command line deserves. -job always runs the daemon (one platform job);
// -daemon given decides (deprecated when true: it is the default); a
// one-shot flag, or a CI job, runs once; anything else runs the daemon.
func resolveDaemonMode(fs *flag.FlagSet, daemonFlag bool, jobID string, getenv func(string) string) (bool, []string) {
	var warns []string
	daemonSet := flagWasSet(fs, "daemon")
	if daemonSet && daemonFlag {
		warns = append(warns, "-daemon is deprecated: the daemon is the default mode; the flag will be removed")
	}
	switch {
	case jobID != "":
		return true, warns
	case daemonSet:
		return daemonFlag, warns
	}
	for _, name := range oneShotFlags {
		if flagWasSet(fs, name) {
			return false, warns
		}
	}
	// A CI job (CI=true, as the per-tool images set) keeps running once, so
	// an existing pipeline that passes only -config does not turn into a
	// daemon.
	if inCI(getenv) {
		return false, warns
	}
	return true, warns
}

// resolveCommands reports whether the daemon takes platform commands:
// -enable-commands given decides (deprecated when true: it is the default),
// then sensor.enable_commands in the config file, then -standalone (off).
// A daemon otherwise takes commands; a one-shot run never does.
func resolveCommands(fs *flag.FlagSet, flagVal bool, configured *bool, standalone, daemon bool) (bool, []string) {
	if flagWasSet(fs, "enable-commands") {
		if flagVal {
			return true, []string{"-enable-commands is deprecated: a daemon takes platform commands by default; the flag will be removed"}
		}
		return false, nil
	}
	switch {
	case configured != nil:
		return *configured, nil
	case standalone:
		return false, nil
	default:
		return daemon, nil
	}
}

// ignoredFlagWarnings names the leftover flags of the removed platform mode
// that were given: they do nothing.
func ignoredFlagWarnings(fs *flag.FlagSet) []string {
	var warns []string
	for _, name := range append(append([]string{}, removedPlatformBoolFlags...), removedPlatformFlags...) {
		if flagWasSet(fs, name) {
			warns = append(warns, fmt.Sprintf("-%s is ignored: %s", name, deprecatedIgnoredMsg))
		}
	}
	return warns
}
