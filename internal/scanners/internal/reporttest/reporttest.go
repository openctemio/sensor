// Package reporttest helps test that scanners keep their reports out of the
// scanned tree.
package reporttest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FakeTool writes a shell script standing in for a scanner binary, for tests.
// It writes content to the report path the scanner passes it (after
// --report-path or --output, or as --output=PATH), creates the directory
// after "database create" (CodeQL), and appends every report or database
// path it was given to the returned log file, one per line.
func FakeTool(t *testing.T, content string) (binary, pathsLog string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "fake-tool")
	pathsLog = filepath.Join(dir, "paths.log")
	script := `#!/bin/sh
log='` + pathsLog + `'
if [ "$1" = database ] && [ "$2" = create ]; then
  echo "$3" >> "$log"
  mkdir -p "$3" || exit 3
  exit 0
fi
prev=""
for a in "$@"; do
  case "$a" in
    --output=*) out="${a#--output=}";;
    *) if [ "$prev" = --report-path ] || [ "$prev" = --output ]; then out="$a"; fi;;
  esac
  prev="$a"
done
echo "$out" >> "$log"
printf '%s' '` + strings.ReplaceAll(content, "'", `'\''`) + `' > "$out" || exit 3
exit 0
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil { //nolint:gosec // test helper script must be executable
		t.Fatal(err)
	}
	return binary, pathsLog
}

// ReadOnlyTarget returns a directory the current user cannot write to, so a
// scanner that tries to put its report into the scanned tree fails.
func ReadOnlyTarget(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory is still writable")
	}
	dir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { //nolint:gosec // deliberately read-only
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) }) //nolint:gosec // restore so TempDir cleanup works
	return dir
}

// AssertOutsideAndRemoved checks every path the fake tool logged is outside
// target and no longer exists after the scan.
func AssertOutsideAndRemoved(t *testing.T, pathsLog, target string) {
	t.Helper()
	data, err := os.ReadFile(pathsLog) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatalf("fake tool was not run: %v", err)
	}
	paths := strings.Fields(string(data))
	if len(paths) == 0 {
		t.Fatal("fake tool logged no path")
	}
	for _, p := range paths {
		if rel, err := filepath.Rel(target, p); err == nil && filepath.IsLocal(rel) {
			t.Errorf("tool was told to write %s, inside the scanned tree %s", p, target)
		}
		if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
			t.Errorf("temporary directory %s still exists after the scan (err=%v)", filepath.Dir(p), err)
		}
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("scanned tree changed: %d entries, want only main.go", len(entries))
	}
}
