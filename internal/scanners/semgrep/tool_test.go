package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
	"github.com/openctemio/sensor/internal/toolrun"
)

func scanWith(t *testing.T, mode, bin, target string) *core.ScanResult {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, mode)
	s := NewScanner()
	s.Binary = bin
	s.SetVersion("1.50.0")
	res, err := s.Scan(context.Background(), target, &core.ScanOptions{Exclude: []string{"vendor"}})
	if err != nil {
		t.Fatalf("%q: %v", mode, err)
	}
	return res
}

// semgrep out of process returns the same report bytes as the direct path
// (the report still lands outside the scanned tree and is removed), so the
// sensor's parser with the command's options gives the same CTIS.
func TestSemgrepOutOfProcessParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "semgrep.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := reporttest.ReadOnlyTarget(t)
	bin, log := reporttest.FakeTool(t, string(data))
	direct := scanWith(t, "in-process", bin, target)
	oop := scanWith(t, "", bin, target)
	reporttest.AssertOutsideAndRemoved(t, log, target)
	if string(direct.RawOutput) != string(oop.RawOutput) || direct.ExitCode != oop.ExitCode || oop.ScannerVersion != "1.50.0" {
		t.Fatalf("results differ: direct %d bytes exit %d, out of process %d bytes exit %d version %q",
			len(direct.RawOutput), direct.ExitCode, len(oop.RawOutput), oop.ExitCode, oop.ScannerVersion)
	}
	opts := &core.ParseOptions{ToolName: "semgrep", AssetType: "repository", AssetValue: "github.com/acme/app",
		Branch: "main", CommitSHA: "abc123", BasePath: "src"}
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

// A semgrep failure (exit 2) fails the scan out of process as on the
// direct path.
func TestSemgrepFailureOutOfProcess(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "semgrep")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'invalid rule' >&2\nexit 2\n"), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	s := NewScanner()
	s.Binary = bin
	if _, err := s.Scan(context.Background(), dir, nil); err == nil {
		t.Fatal("a failed semgrep run succeeded")
	}
}

func TestSemgrepManifest(t *testing.T) {
	if err := ToolManifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := NewScanner().ToolContract(); c == nil || c.Digest != ToolManifest.Contract().Digest {
		t.Fatalf("tool contract %+v", c)
	}
}
