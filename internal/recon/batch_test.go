package recon

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
	"github.com/openctemio/sensor/internal/toolrun"
)

// countingHTTPX is the batch fake httpx that also records each process it
// starts and prints a line naming an input the job does not carry.
func countingHTTPX(t *testing.T) (*Scanner, string) {
	t.Helper()
	data, err := os.ReadFile(flagcheck.Testdata("httpx-1.12.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out.jsonl")
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	bin := filepath.Join(dir, "httpx")
	script := "#!/bin/sh\necho run >> " + calls + "\n" +
		`printf '{"input":"https://evil.example","url":"https://evil.example","status_code":200,"title":"not asked"}\n'` + "\n" +
		httpxListBody(out, "0")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := New("httpx")
	if err != nil {
		t.Fatal(err)
	}
	hx := s.Recon().(*httpx.Scanner)
	hx.Binary = bin
	hx.SetVersion("v1.12.0")
	return s, calls
}

// httpx runs a job's whole list as one process; a target it printed no
// line for gets an explicit failed outcome (the job still completes), and a
// line naming an input the job does not carry is never read (both paths).
func TestHTTPXBatch_OneProcessExplicitOutcomes(t *testing.T) {
	for _, runtime := range []string{"in-process", ""} {
		t.Run("runtime="+runtime, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, runtime)
			s, calls := countingHTTPX(t)
			targets := []string{"https://example.com", "https://bad.example", "https://a.example", "https://b.example"}
			res, err := s.ScanTargets(context.Background(), targets, nil)
			if err != nil {
				t.Fatalf("one target without a line failed the job: %v", err)
			}
			raw, _ := os.ReadFile(calls)
			if n := strings.Count(string(raw), "run"); n != 1 {
				t.Fatalf("%d httpx processes for %d targets", n, len(targets))
			}
			rep := parse(t, res.RawOutput)
			if got := failedTargetValues(t, rep.Properties["failed_targets"]); !slices.Equal(got, []string{"https://bad.example"}) {
				t.Fatalf("failed_targets %v", got)
			}
			if strings.Contains(string(res.RawOutput), "evil.example") || strings.Contains(string(res.RawOutput), "not asked") {
				t.Fatal("a line for an input the job does not carry reached the report")
			}
			if len(rep.Assets) == 0 {
				t.Fatal("the targets' results were lost")
			}
		})
	}
}
