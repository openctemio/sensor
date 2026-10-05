package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

// The SDK's credentials error for this daemon keeps the sensor's wording:
// what needs the platform, what is missing and how to set it.
func TestDaemonCredentialsHelp(t *testing.T) {
	err := sensorkit.CheckDaemonCredentials("", daemonCredentialsHelp)
	if !errors.Is(err, sensorkit.ErrNeedsPlatform) || sensorkit.ExitCode(err) != 2 {
		t.Fatalf("err = %v (exit %d)", err, sensorkit.ExitCode(err))
	}
	want := "a server-controlled daemon (-daemon -enable-commands) needs the platform URL and a sensor API key; missing: [API_URL].\n" +
		"  Set API_URL (docker run -e API_URL=https://<platform>/ ..., -api-url, or api.base_url in the -config file).\n" +
		"  Without API_KEY the sensor pairs on first start: it prints a code and a fingerprint for an\n" +
		"  administrator to approve under Sensors > Pair a sensor (or run `openctemio-sensor pair` first).\n" +
		"  To scan without a platform, run a one-shot scan instead: -tool <name> -target <path>"
	// No API key is not an error: the daemon pairs (api RFC-052).
	if err := sensorkit.CheckDaemonCredentials("https://platform.example", daemonCredentialsHelp); err != nil {
		t.Fatalf("no key: %v", err)
	}
	if err.Error() != want {
		t.Fatalf("message:\n%s\nwant:\n%s", err, want)
	}
}

func TestUnavailableReasonSeparatesMissingFromBroken(t *testing.T) {
	dir := t.TempDir()
	broken := "#!/bin/sh\necho \"ModuleNotFoundError: No module named 'pkg_resources'\" >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "semgrep"), []byte(broken), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	got := unavailableReason(context.Background(), ScannerConfig{Name: "semgrep"}, nil)
	if !strings.Contains(got, "installed but fails to run") || !strings.Contains(got, "pkg_resources") {
		t.Errorf("broken semgrep: %q", got)
	}
	got = unavailableReason(context.Background(), ScannerConfig{Name: "trivy-fs"}, nil)
	if !strings.HasPrefix(got, "not installed") || !strings.Contains(got, "trivy") {
		t.Errorf("missing trivy: %q", got)
	}
}
