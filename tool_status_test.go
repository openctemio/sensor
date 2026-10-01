package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDaemonCredentials(t *testing.T) {
	cases := []struct {
		name                         string
		daemon, standalone, commands bool
		url, key                     string
		wantMissing                  []string
	}{
		{name: "one-shot run needs nothing", daemon: false, commands: true},
		{name: "standalone daemon needs nothing", daemon: true, standalone: true, commands: true},
		{name: "scheduled-only daemon needs nothing", daemon: true},
		{name: "server-controlled daemon with both", daemon: true, commands: true, url: "https://p", key: "k"},
		{name: "server-controlled daemon without URL", daemon: true, commands: true, key: "k", wantMissing: []string{"API_URL"}},
		{name: "server-controlled daemon without anything", daemon: true, commands: true, wantMissing: []string{"API_URL", "API_KEY"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkDaemonCredentials(c.daemon, c.standalone, c.commands, c.url, c.key)
			if len(c.wantMissing) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, errDaemonNeedsPlatform) {
				t.Fatalf("err = %v, want errDaemonNeedsPlatform", err)
			}
			for _, v := range c.wantMissing {
				if !strings.Contains(err.Error(), v) {
					t.Errorf("error does not name %s: %v", v, err)
				}
			}
			if !strings.Contains(err.Error(), "-e API_URL=") {
				t.Errorf("error does not say how to set the variables: %v", err)
			}
		})
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
