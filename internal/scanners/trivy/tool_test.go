package trivy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// fakeTrivy writes a script standing in for trivy: it prints out (stdout)
// and the value of TRIVY_PASSWORD it was given to the file passwordSeen.
func fakeTrivy(t *testing.T, out []byte) (bin, passwordSeen string) {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "out.json")
	if err := os.WriteFile(data, out, 0o600); err != nil {
		t.Fatal(err)
	}
	passwordSeen = filepath.Join(dir, "password")
	bin = filepath.Join(dir, "trivy")
	script := "#!/bin/sh\nprintf '%s' \"$TRIVY_PASSWORD\" > " + passwordSeen + "\ncat " + data + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	return bin, passwordSeen
}

func corpus(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "trivy-fs.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func scanWith(t *testing.T, mode string, bin, target string) *core.ScanResult {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, mode)
	s := NewScanner()
	s.Binary = bin
	s.SetVersion("0.62.1")
	res, err := s.Scan(context.Background(), target, &core.ScanOptions{Exclude: []string{"vendor"}})
	if err != nil {
		t.Fatalf("%q: %v", mode, err)
	}
	return res
}

// trivy out of process returns the same bytes as the direct path, so the
// sensor's parser (with the command's asset and branch) gives the same CTIS.
func TestTrivyOutOfProcessParity(t *testing.T) {
	bin, _ := fakeTrivy(t, corpus(t))
	target := t.TempDir()
	direct := scanWith(t, "in-process", bin, target)
	oop := scanWith(t, "", bin, target)
	if string(direct.RawOutput) != string(oop.RawOutput) || direct.ExitCode != oop.ExitCode || oop.ScannerVersion != "0.62.1" {
		t.Fatalf("results differ: direct %d bytes exit %d, out of process %d bytes exit %d version %q",
			len(direct.RawOutput), direct.ExitCode, len(oop.RawOutput), oop.ExitCode, oop.ScannerVersion)
	}
	opts := &core.ParseOptions{ToolName: "trivy", AssetType: "repository", AssetValue: "github.com/acme/app", Branch: "main", CommitSHA: "abc123"}
	a, err := (&Parser{}).Parse(context.Background(), direct.RawOutput, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&Parser{}).Parse(context.Background(), oop.RawOutput, opts)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := toolrun.NormalizeReport(a)
	nb, _ := toolrun.NormalizeReport(b)
	if string(na) != string(nb) || len(b.Findings) == 0 {
		t.Fatalf("CTIS differs or is empty\n--- direct\n%s\n--- out of process\n%s", na, nb)
	}
}

// The registry password reaches trivy through the scanner environment, as
// on the direct path, and is never part of the task the child receives.
func TestTrivyRegistryPasswordNeverInTheTask(t *testing.T) {
	const secret = "s3cr3t-registry-password"
	t.Setenv("TRIVY_PASSWORD", secret)
	bin, seen := fakeTrivy(t, corpus(t))
	s := NewScanner()
	s.Binary = bin
	local, err := json.Marshal(trivyLocal{Scanner: s, Scan: core.ScanOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(local), secret) {
		t.Fatal("the task carries the registry password")
	}
	scanWith(t, "", bin, t.TempDir())
	got, err := os.ReadFile(seen) //nolint:gosec // test-owned path
	if err != nil || string(got) != secret {
		t.Fatalf("trivy did not get the registry password (%q, %v)", got, err)
	}
}

// A relative target is resolved by the sensor, not in the child's task
// directory.
func TestTrivyRelativeTargetResolvedByTheSensor(t *testing.T) {
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args")
	bin := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\necho \"$*\" > " + argsLog + "\necho '{}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.Mkdir("repo", 0o750); err != nil {
		t.Fatal(err)
	}
	scanWith(t, "", bin, "repo")
	got, _ := os.ReadFile(argsLog) //nolint:gosec // test-owned path
	if !strings.Contains(string(got), filepath.Join(dir, "repo")) {
		t.Fatalf("trivy scanned %q, not the sensor's %s", got, filepath.Join(dir, "repo"))
	}
}

// Output beyond the runtime's artifact limit fails the scan; it is never
// truncated into a partial report.
func TestTrivyOversizedOutputFails(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 65 MiB")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\nhead -c 68157440 /dev/zero | tr '\\0' 'a'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	s := NewScanner()
	s.Binary = bin
	if res, err := s.Scan(context.Background(), dir, nil); err == nil {
		t.Fatalf("an oversized output was accepted (%d bytes)", len(res.RawOutput))
	}
}

func TestTrivyManifest(t *testing.T) {
	if err := ToolManifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := NewScanner().ToolContract(); c == nil || c.Digest != ToolManifest.Contract().Digest {
		t.Fatalf("tool contract %+v", c)
	}
}
