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
	err := sensorkit.CheckCredentials("", "k", daemonCredentialsHelp)
	if !errors.Is(err, sensorkit.ErrNeedsPlatform) || sensorkit.ExitCode(err) != 2 {
		t.Fatalf("err = %v (exit %d)", err, sensorkit.ExitCode(err))
	}
	want := "a server-controlled daemon (-daemon -enable-commands) needs the platform URL and a sensor API key; missing: [API_URL].\n" +
		"  Set them as environment variables (docker run -e API_URL=https://<platform>/ -e API_KEY=<key> ...),\n" +
		"  as -api-url / -api-key flags, or as api.base_url / api.api_key in the -config file.\n" +
		"  Create the key in the platform: Settings > Sensors (it is shown once).\n" +
		"  To scan without a platform, run a one-shot scan instead: -tool <name> -target <path>"
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
