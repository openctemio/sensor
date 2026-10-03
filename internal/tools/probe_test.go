package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBinary writes an executable script named name into a fresh PATH dir.
func fakeBinary(t *testing.T, name, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestProbeAvailable(t *testing.T) {
	fakeBinary(t, "trivy", `echo "Version: 0.69.3"`)
	st := Probe(context.Background(), "trivy")
	if st.State != Available || st.Version != "0.69.3" {
		t.Fatalf("got %+v, want available 0.69.3", st)
	}
	if got := st.Describe(); got != "available: 0.69.3" {
		t.Errorf("Describe = %q", got)
	}
}

func TestProbeNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	st := Probe(context.Background(), "semgrep")
	if st.State != NotInstalled || st.Describe() != "not installed" {
		t.Fatalf("got %+v (%s), want not installed", st, st.Describe())
	}
}

// The v0.3.0 image bug: semgrep is on PATH but dies on import. That is a
// broken tool, reported with its own error, never "not installed".
func TestProbeInstalledButBroken(t *testing.T) {
	fakeBinary(t, "semgrep", `echo "Traceback (most recent call last):" >&2
echo "ModuleNotFoundError: No module named 'pkg_resources'" >&2
exit 1`)
	st := Probe(context.Background(), "semgrep")
	if st.State != Broken {
		t.Fatalf("state = %v, want Broken", st.State)
	}
	d := st.Describe()
	for _, want := range []string{"BROKEN", "installed", "semgrep --version", "pkg_resources"} {
		if !strings.Contains(d, want) {
			t.Errorf("Describe() = %q, missing %q", d, want)
		}
	}
	if ok, _, err := CheckInstalled(context.Background(), "semgrep"); ok || err == nil || !strings.Contains(err.Error(), "pkg_resources") {
		t.Errorf("CheckInstalled = %v, %v; want false with the tool's error", ok, err)
	}
}

func TestBinaryFor(t *testing.T) {
	for in, want := range map[string]string{
		"trivy-fs": "trivy", "trivy-config": "trivy", "trivy": "trivy",
		"semgrep": "semgrep", "nuclei": "nuclei", "custom-tool": "custom-tool",
	} {
		if got := BinaryFor(in); got != want {
			t.Errorf("BinaryFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVersionNucleiStripsColor(t *testing.T) {
	out := "\x1b[34mINF\x1b[0m] PDCP Directory: /root/.pdcp\n[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.4.1\n"
	if got := ParseVersion("nuclei", out); got != "v3.4.1" {
		t.Errorf("ParseVersion(nuclei) = %q, want v3.4.1", got)
	}
}

// The probe runs with the scanner environment: the sensor's key and other
// credentials never reach the probed binary.
func TestProbeDoesNotSeeSensorSecrets(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "env.txt")
	fakeBinary(t, "trivy", "export -p > "+dump+"\necho \"Version: 0.69.3\"")
	for _, name := range []string{"API_KEY", "SENSOR_API_KEY", "OPENCTEM_API_KEY", "SENSOR_OUTBOX_KEY_FILE", "GITHUB_TOKEN", "DB_PASSWORD"} {
		t.Setenv(name, "must_not_leak")
	}
	if st := Probe(context.Background(), "trivy"); st.State != Available {
		t.Fatalf("got %+v", st)
	}
	raw, err := os.ReadFile(dump) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	if env := string(raw); strings.Contains(env, "must_not_leak") || !strings.Contains(env, "PATH") {
		t.Fatalf("probe environment:\n%s", env)
	}
}

// The ProjectDiscovery recon tools print a banner, then the version on an
// [INF] line (katana 1.7 spells "Current version:").
func TestParseVersionReconTools(t *testing.T) {
	for tool, out := range map[string]string{
		"subfinder": "\n  __\n\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current Version: v2.16.0\n[INF] Subfinder Config Directory: /home/x\n",
		"dnsx":      "[INF] Current Version: 1.3.1\n",
		"naabu":     "[INF] Current Version: 2.6.1\n",
		"httpx":     "  __\n[INF] Current Version: v1.12.0\n",
		"katana":    "   __        __\n\t\tprojectdiscovery.io\n\n[INF] Current version: v1.7.0\n",
	} {
		want := map[string]string{"subfinder": "v2.16.0", "dnsx": "1.3.1", "naabu": "2.6.1", "httpx": "v1.12.0", "katana": "v1.7.0"}[tool]
		if got := ParseVersion(tool, out); got != want {
			t.Errorf("ParseVersion(%s) = %q, want %q", tool, got, want)
		}
	}
}
