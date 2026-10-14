package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// modeFlags is the part of the sensor's flag set the mode rule reads.
func modeFlags(t *testing.T, args ...string) (*flag.FlagSet, *bool, *bool) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	daemon := fs.Bool("daemon", false, "")
	cmds := fs.Bool("enable-commands", false, "")
	fs.String("tool", "", "")
	fs.String("tools", "", "")
	fs.String("target", ".", "")
	fs.Bool("push", false, "")
	fs.Bool("json", false, "")
	fs.String("output", "", "")
	fs.Bool("standalone", false, "")
	for _, n := range removedPlatformBoolFlags {
		fs.Bool(n, false, "")
	}
	for _, n := range removedPlatformFlags {
		fs.String(n, "", "")
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs, daemon, cmds
}

func noEnv(string) string { return "" }

func TestResolveDaemonMode(t *testing.T) {
	ci := func(k string) string {
		if k == "CI" {
			return "true"
		}
		return ""
	}
	cases := []struct {
		name     string
		args     []string
		job      string
		env      func(string) string
		want     bool
		wantWarn bool
	}{
		{"minimal run: daemon", nil, "", noEnv, true, false},
		{"-tools alone: daemon (narrowing)", []string{"-tools", "nuclei"}, "", noEnv, true, false},
		{"-daemon: daemon, deprecated", []string{"-daemon"}, "", noEnv, true, true},
		{"-daemon=false: one run", []string{"-daemon=false"}, "", noEnv, false, false},
		{"-tool: one run", []string{"-tool", "semgrep"}, "", noEnv, false, false},
		{"-target: one run", []string{"-tools", "a,b", "-target", "."}, "", noEnv, false, false},
		{"-push: one run", []string{"-push"}, "", noEnv, false, false},
		{"-json: one run", []string{"-json"}, "", noEnv, false, false},
		{"-output: one run", []string{"-output", "r.json"}, "", noEnv, false, false},
		{"-daemon with -tool: daemon", []string{"-daemon", "-tool", "nuclei"}, "", noEnv, true, true},
		{"CI job: one run", nil, "", ci, false, false},
		{"-job: daemon", []string{"-daemon=false"}, "job-1", noEnv, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, daemon, _ := modeFlags(t, tc.args...)
			got, warns := resolveDaemonMode(fs, *daemon, tc.job, tc.env)
			if got != tc.want {
				t.Fatalf("daemon = %v, want %v", got, tc.want)
			}
			if (len(warns) > 0) != tc.wantWarn {
				t.Fatalf("warnings %v", warns)
			}
		})
	}
}

func TestResolveCommands(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name       string
		args       []string
		configured *bool
		standalone bool
		daemon     bool
		want       bool
		wantWarn   bool
	}{
		{"daemon default: on", nil, nil, false, true, true, false},
		{"one run: off", nil, nil, false, false, false, false},
		{"-enable-commands: on, deprecated", []string{"-enable-commands"}, nil, false, true, true, true},
		{"-enable-commands=false opts out", []string{"-enable-commands=false"}, &yes, false, true, false, false},
		{"enable_commands: false opts out", nil, &no, false, true, false, false},
		{"enable_commands: true", nil, &yes, false, true, true, false},
		{"-standalone: off", nil, nil, true, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, _, cmds := modeFlags(t, tc.args...)
			got, warns := resolveCommands(fs, *cmds, tc.configured, tc.standalone, tc.daemon)
			if got != tc.want {
				t.Fatalf("commands = %v, want %v", got, tc.want)
			}
			if (len(warns) > 0) != tc.wantWarn {
				t.Fatalf("warnings %v", warns)
			}
		})
	}
}

func TestIgnoredFlagWarnings(t *testing.T) {
	fs, _, _ := modeFlags(t, "-enable-recon", "-enable-vulnscan=false", "-bootstrap-token", "x")
	warns := ignoredFlagWarnings(fs)
	if len(warns) != 3 {
		t.Fatalf("warnings %v", warns)
	}
	for _, w := range warns {
		if !strings.Contains(w, "is ignored") || !strings.Contains(w, "tools.allow") {
			t.Fatalf("warning %q", w)
		}
	}
	fs, _, _ = modeFlags(t)
	if w := ignoredFlagWarnings(fs); len(w) != 0 {
		t.Fatalf("no flags, warnings %v", w)
	}
}

// A minimal start (no -daemon, -enable-commands or -tools) is the daemon
// with platform commands: without SENSOR_API_URL it stops with the
// credentials help (exit 2) instead of "No scanners configured".
func TestMinimalRunIsACommandDaemon(t *testing.T) {
	if inChild() {
		return
	}
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("SENSOR_API_URL", "")
	t.Setenv("SENSOR_TOOLS", "")
	out, code := runMainInChild(t, "TestMinimalRunIsACommandDaemon", "-enable-recon")
	if code != 2 || !strings.Contains(out, "SENSOR_API_URL") || strings.Contains(out, "No scanners") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	if !strings.Contains(out, "-enable-recon is ignored") {
		t.Fatalf("no warning for the ignored flag:\n%s", out)
	}
}
