package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/scanners/importparse"
)

// fakeNucleiBinary records the -l list file (mode and content) and prints one
// result per listed target.
func fakeNucleiBinary(t *testing.T) (bin, recordDir string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "nuclei")
	script := `#!/bin/sh
list=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-l" ]; then list="$2"; fi
  shift
done
[ -n "$list" ] || { echo "no -l" >&2; exit 2; }
stat -c %a "$list" > "` + dir + `/perm"
cp "$list" "` + dir + `/list"
echo "$list" > "` + dir + `/path"
while IFS= read -r t; do
  printf '{"template-id":"tech-detect","info":{"name":"t","severity":"info"},"host":"%s","matched-at":"%s"}\n' "$t" "$t"
done < "$list"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

func TestScanTargetsUsesPrivateListFile(t *testing.T) {
	bin, rec := fakeNucleiBinary(t)
	s := NewScanner()
	s.Binary = bin
	targets := []string{"http://203.0.113.10", "http://203.0.113.11:8080", "203.0.113.12"}
	mode, file := s.Mode, s.TargetFile

	res, err := s.ScanTargets(context.Background(), targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(rec, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read("perm"); got != "600" {
		t.Errorf("target list mode %s, want 600", got)
	}
	if got := read("list"); got != strings.Join(targets, "\n") {
		t.Errorf("target list = %q", got)
	}
	if _, err := os.Stat(read("path")); !os.IsNotExist(err) {
		t.Errorf("target list was not removed after the run (%v)", err)
	}
	r, err := importparse.Nuclei().Parse(context.Background(), res.RawOutput, nil)
	if err != nil || len(r.Findings) != len(targets) {
		t.Fatalf("want one finding per target, got %v, %v", r, err)
	}
	if s.Mode != mode || s.TargetFile != file {
		t.Error("ScanTargets must not change the scanner's Mode or TargetFile")
	}
}

func TestScanTargetsRejectsUnsafeLists(t *testing.T) {
	bin, _ := fakeNucleiBinary(t)
	s := NewScanner()
	s.Binary = bin
	for name, list := range map[string][]string{
		"empty list":        nil,
		"newline injection": {"203.0.113.10\n169.254.169.254"},
		"carriage return":   {"203.0.113.10\r"},
		"blank entry":       {"203.0.113.10", " "},
		"flag-like entry":   {"-config=/tmp/x"},
	} {
		if _, err := s.ScanTargets(context.Background(), list, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := make([]string, MaxListTargets+1)
	for i := range tooMany {
		tooMany[i] = "203.0.113.10"
	}
	if _, err := s.ScanTargets(context.Background(), tooMany, nil); err == nil {
		t.Error("more than MaxListTargets targets accepted")
	}
}
