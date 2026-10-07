package betterleaks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/importparse"
	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
	"github.com/openctemio/sensor/internal/toolrun"
)

func genericScanWith(t *testing.T, mode, bin, target string, opts *core.ScanOptions) *core.ScanResult {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, mode)
	s := NewScanner()
	s.Binary = bin
	s.SetVersion("1.1.0")
	res, err := s.GenericScan(context.Background(), target, opts)
	if err != nil {
		t.Fatalf("%q: %v", mode, err)
	}
	return res
}

// betterleaks out of process returns the same report bytes as the direct
// path (exclusions applied the same way, the report outside the scanned
// tree and removed), so the sensor's parser gives the same CTIS.
func TestBetterleaksOutOfProcessParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "betterleaks.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := reporttest.ReadOnlyTarget(t)
	bin, log := reporttest.FakeTool(t, string(data))
	opts := &core.ScanOptions{Exclude: []string{"vendor"}}
	direct := genericScanWith(t, "in-process", bin, target, opts)
	oop := genericScanWith(t, "", bin, target, opts)
	reporttest.AssertOutsideAndRemoved(t, log, target)
	if string(direct.RawOutput) != string(oop.RawOutput) || direct.ExitCode != oop.ExitCode || oop.ScannerVersion != "1.1.0" {
		t.Fatalf("results differ: direct %d bytes exit %d, out of process %d bytes exit %d version %q",
			len(direct.RawOutput), direct.ExitCode, len(oop.RawOutput), oop.ExitCode, oop.ScannerVersion)
	}
	popts := &core.ParseOptions{ToolName: "betterleaks", AssetType: "repository", AssetValue: "github.com/acme/app", Branch: "main"}
	a, err := importparse.Betterleaks().Parse(context.Background(), direct.RawOutput, popts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := importparse.Betterleaks().Parse(context.Background(), oop.RawOutput, popts)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := toolrun.NormalizeReport(a)
	nb, _ := toolrun.NormalizeReport(b)
	if string(na) != string(nb) || len(b.Findings) == 0 {
		t.Fatalf("CTIS differs or is empty\n--- direct\n%s\n--- out of process\n%s", na, nb)
	}
}

// An unexpected betterleaks exit fails the scan out of process.
func TestBetterleaksFailureOutOfProcess(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "betterleaks")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'bad config' >&2\nexit 126\n"), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	s := NewScanner()
	s.Binary = bin
	if _, err := s.GenericScan(context.Background(), dir, nil); err == nil {
		t.Fatal("a failed betterleaks run succeeded")
	}
}

func TestBetterleaksManifest(t *testing.T) {
	if err := ToolManifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := NewScanner().ToolContract(); c == nil || c.Digest != ToolManifest.Contract().Digest {
		t.Fatalf("tool contract %+v", c)
	}
}
