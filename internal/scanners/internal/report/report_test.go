package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathDefaultGoesToTempDirAndIsCleanedUp(t *testing.T) {
	target := t.TempDir()
	p, cleanup, err := Path("", "gitleaks-report.json", "gitleaks")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "gitleaks-report.json" {
		t.Errorf("report name = %q, want gitleaks-report.json", filepath.Base(p))
	}
	if rel, err := filepath.Rel(target, p); err == nil && filepath.IsLocal(rel) {
		t.Fatalf("report %s is inside the target %s", p, target)
	}
	dir := filepath.Dir(p)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("report directory %s not created: %v", dir, err)
	}
	if err := os.WriteFile(p, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("report directory %s still exists after cleanup (err=%v)", dir, err)
	}
}

func TestPathRelativeKeepsOnlyTheBaseName(t *testing.T) {
	p, cleanup, err := Path("out/../../my.json", "default.json", "semgrep")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if filepath.Base(p) != "my.json" {
		t.Errorf("report name = %q, want my.json", filepath.Base(p))
	}
	if filepath.Base(filepath.Dir(filepath.Dir(p))) == "out" {
		t.Errorf("relative directories must not be kept: %s", p)
	}
}

func TestPathAbsoluteIsUsedAsIs(t *testing.T) {
	want := filepath.Join(t.TempDir(), "report.sarif")
	p, cleanup, err := Path(want, "default.sarif", "codeql")
	if err != nil {
		t.Fatal(err)
	}
	if p != want {
		t.Errorf("path = %q, want %q", p, want)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(p); err != nil {
		t.Errorf("cleanup removed the caller's absolute report path: %v", err)
	}
}

func TestPathTwoCallsDoNotCollide(t *testing.T) {
	a, ca, err := Path("", "r.json", "gitleaks")
	if err != nil {
		t.Fatal(err)
	}
	defer ca()
	b, cb, err := Path("", "r.json", "gitleaks")
	if err != nil {
		t.Fatal(err)
	}
	defer cb()
	if a == b {
		t.Fatalf("two scans got the same report path %s", a)
	}
}
