package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// realVersionOutput is `nuclei -version` captured from the openctem sensor
// image (nuclei v3.11.1): nothing on stdout, a colored banner on stderr.
const realVersionOutput = "[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1\n" +
	"[\x1b[34mINF\x1b[0m] Nuclei Config Directory: /home/openctem/.config/nuclei\n" +
	"[\x1b[34mINF\x1b[0m] Nuclei Cache Directory: /home/openctem/.cache/nuclei\n" +
	"[\x1b[34mINF\x1b[0m] PDCP Directory: /home/openctem/.pdcp\n"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"engine line, colors removed", "[INF] Nuclei Engine Version: v3.11.1\n[INF] Nuclei Config Directory: /x\n", "v3.11.1"},
		{"engine line not first", "[INF] Nuclei Config Directory: /x\n[INF] Nuclei Engine Version: v3.2.0\n", "v3.2.0"},
		{"older current version", "[INF] Current Version: v2.9.15\n", "v2.9.15"},
		{"bare", "v3.0.0\n", "v3.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVersion(tt.in); got != tt.want {
				t.Fatalf("parseVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// IsInstalled must report the version of a nuclei that prints its banner
// only to stderr, in color (the v3 behavior that left the version blank).
func TestIsInstalledReadsStderrBanner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary")
	}
	dir := t.TempDir()
	banner := filepath.Join(dir, "banner.txt")
	if err := os.WriteFile(banner, []byte(realVersionOutput), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "nuclei")
	script := "#!/bin/sh\ncat '" + banner + "' >&2\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test fake binary must be executable
		t.Fatal(err)
	}

	s := NewScanner()
	s.Binary = bin
	installed, version, err := s.IsInstalled(context.Background())
	if err != nil || !installed {
		t.Fatalf("IsInstalled = %v, %v; want installed", installed, err)
	}
	if version != "v3.11.1" {
		t.Fatalf("version = %q, want v3.11.1", version)
	}
	if s.Version() != "v3.11.1" {
		t.Fatalf("Version() = %q, want v3.11.1", s.Version())
	}
}
