package codeql

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
	"github.com/openctemio/sensor/internal/toolrun"
)

func scanWith(t *testing.T, mode, bin, target string) *core.ScanResult {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, mode)
	s := NewSecurityScanner(LanguageGo)
	s.Binary = bin
	s.SetVersion("2.23.0")
	res, err := s.Scan(context.Background(), target, nil)
	if err != nil {
		t.Fatalf("%q: %v", mode, err)
	}
	return res
}

// CodeQL out of process builds its per-scan database and writes its report
// outside the scanned tree, as the direct path does, and returns the same
// SARIF, so the SDK SARIF parser gives the same CTIS.
func TestCodeQLOutOfProcessParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "codeql-provenance.sarif.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := reporttest.ReadOnlyTarget(t)
	bin, log := reporttest.FakeTool(t, string(data))
	direct := scanWith(t, "in-process", bin, target)
	oop := scanWith(t, "", bin, target)
	reporttest.AssertOutsideAndRemoved(t, log, target)
	if string(direct.RawOutput) != string(oop.RawOutput) || direct.ExitCode != oop.ExitCode || oop.ScannerVersion != "2.23.0" {
		t.Fatalf("results differ: direct %d bytes exit %d, out of process %d bytes exit %d version %q",
			len(direct.RawOutput), direct.ExitCode, len(oop.RawOutput), oop.ExitCode, oop.ScannerVersion)
	}
	popts := &core.ParseOptions{ToolName: "codeql", AssetType: "repository", AssetValue: "github.com/acme/app", Branch: "main"}
	a, err := (&core.SARIFParser{}).Parse(context.Background(), direct.RawOutput, popts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&core.SARIFParser{}).Parse(context.Background(), oop.RawOutput, popts)
	if err != nil {
		t.Fatal(err)
	}
	na, _ := toolrun.NormalizeReport(a)
	nb, _ := toolrun.NormalizeReport(b)
	if string(na) != string(nb) || len(b.Findings) == 0 {
		t.Fatalf("CTIS differs or is empty\n--- direct\n%s\n--- out of process\n%s", na, nb)
	}
}

// A configured database path is resolved by the sensor and is the child's
// only extra write path.
func TestCodeQLDatabasePathResolvedByTheSensor(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "codeql-provenance.sarif.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	bin, log := reporttest.FakeTool(t, string(data))
	t.Setenv(toolrun.EnvRuntime, "")
	s := NewSecurityScanner(LanguageGo)
	s.Binary = bin
	s.DatabasePath = "db"
	if _, err := s.Scan(context.Background(), t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(log) //nolint:gosec // test-owned path
	if want := filepath.Join(dir, "db"); !containsLine(string(got), want) {
		t.Fatalf("database at %q, want %s", got, want)
	}
	if s.DatabasePath != "db" {
		t.Fatal("the shared scanner was modified")
	}
}

func containsLine(s, want string) bool {
	for _, l := range strings.Split(s, "\n") {
		if l == want {
			return true
		}
	}
	return false
}

func TestCodeQLManifest(t *testing.T) {
	if err := ToolManifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if c := NewScanner().ToolContract(); c == nil || c.Digest != ToolManifest.Contract().Digest {
		t.Fatalf("tool contract %+v", c)
	}
}
