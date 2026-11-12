package naabu

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/jobfiles/jobfilestest"
)

// fakeNaabu reads its -l list, records the list's path in record (when it
// can write there) and prints one open port per listed host.
func fakeNaabu(t *testing.T) (bin, record string) {
	t.Helper()
	dir := t.TempDir()
	bin, record = filepath.Join(dir, "naabu"), filepath.Join(dir, "path")
	script := `#!/bin/sh
prev=""; for a in "$@"; do [ "$prev" = "-l" ] && list="$a"; prev="$a"; done
echo "$list" > "` + record + `" 2>/dev/null
while IFS= read -r t; do printf '%s:443\n' "$t"; done < "$list"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, record
}

// SECURITY: the job's targets go into a private job file (never the
// system's temporary directory, where another organization's task on a
// shared sensor could read them), and in the real sandbox naabu still reads
// it: the run gets the context that grants it.
func TestScanBatchTargetListIsPrivateToItsJob(t *testing.T) {
	targets := []string{"192.0.2.10", "192.0.2.11"}
	bin, record := fakeNaabu(t)
	s := NewScanner()
	s.Binary = bin
	if _, err := s.ScanBatch(context.Background(), targets, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	list := strings.TrimSpace(string(raw))
	jobfilestest.AssertUnderTaskRoot(t, list)
	if _, err := os.Stat(list); !os.IsNotExist(err) {
		t.Errorf("target list %s left after the run (%v)", list, err)
	}

	restore, ok := jobfilestest.Sandbox(t)
	if !ok {
		return
	}
	defer restore()
	out, err := s.ScanBatch(context.Background(), targets, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(targets) {
		t.Fatalf("naabu could not read its target list in the sandbox: %v", out)
	}
}
