package recon

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
	"github.com/openctemio/sensor/internal/toolrun"
)

// slowHTTPX is httpx printing the recorded real output for every target,
// taking delay on slow.example (a host that answers late or never).
func slowHTTPX(t *testing.T, delay string) *Scanner {
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
	bin := filepath.Join(dir, "httpx")
	script := "#!/bin/sh\n" + httpxListBody(out, delay)
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
	return s
}

// Live incident 2026-10-14: an httpx task over 72 targets reported 0 done
// until its last target, so the platform read it as stalled, took it back
// three times and failed it. Out of process, each target is now settled the
// moment it ends: the job's progress moves while the run is still going.
func TestToolChildSettlesEachTargetAsItEnds(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	prog := core.NewProgress(0)
	ctx := core.WithProgress(context.Background(), prog)
	targets := []string{"https://a.example", "https://b.example", "https://slow.example"}
	prog.SetTargets(targets)

	var seenMidRun atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
				if n := prog.Snapshot().Done; n > 0 && n < len(targets) {
					seenMidRun.Store(int64(n))
				}
			}
		}
	}()
	_, err := slowHTTPX(t, "3").ScanTargets(ctx, targets, nil)
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	if seenMidRun.Load() != 2 {
		t.Fatalf("progress during the run = %d done, want the 2 finished targets before the slow one ended", seenMidRun.Load())
	}
	if got := prog.Snapshot(); got.Done != 3 {
		t.Fatalf("progress at the end %+v", got)
	}
}

// A target that never answers costs its own budget: httpx runs the list as
// one process whose per-request timeout comes from the per-target budget,
// so only that target waits, the others keep their results, and the job
// completes (both paths).
func TestHungTargetCostsOnlyItsBudget(t *testing.T) {
	for _, runtime := range []string{"in-process", ""} {
		t.Run("runtime="+runtime, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, runtime)
			targets := []string{"https://a.example", "https://slow.example", "https://b.example"}
			start := time.Now()
			// 3 s budget over httpx's 1 try + 2 retries: -timeout 1, floored at 2 s.
			res, err := slowHTTPX(t, "30").ScanTargets(context.Background(), targets, &core.ScanOptions{TargetTimeout: 3 * time.Second})
			if err != nil {
				t.Fatalf("a hung target failed the job: %v", err)
			}
			if took := time.Since(start); took > 15*time.Second {
				t.Fatalf("took %s: the hung target was not bounded by httpx's per-request timeout", took)
			}
			rep := parse(t, res.RawOutput)
			if len(rep.Assets) == 0 {
				t.Fatal("the other targets' results were lost")
			}
			if _, ok := rep.Properties[unfinishedTargetsKey]; ok {
				t.Fatalf("a finished run lists unfinished targets: %v", rep.Properties[unfinishedTargetsKey])
			}
		})
	}
}

// Every target not answering is not the tool failing: the job completes
// with each target settled instead of failing and being retried.
func TestAllTargetsOverBudgetCompletes(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "in-process")
	res, err := slowHTTPX(t, "30").ScanTargets(context.Background(), []string{"https://slow.example"}, &core.ScanOptions{TargetTimeout: time.Second})
	if err != nil {
		t.Fatalf("a target over its budget failed the job: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("result error %q", res.Error)
	}
}

// When the job's time budget ends the run, the finished targets' results
// are returned (partial) with the unfinished targets listed, instead of
// everything being dropped; a cancel returns nothing.
func TestJobBudgetKeepsFinishedTargets(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "in-process")
	targets := []string{"https://a.example", "https://slow.example", "https://b.example"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := slowHTTPX(t, "30").ScanTargets(ctx, targets, nil)
	if err != nil {
		t.Fatalf("the budget-stopped run failed: %v", err)
	}
	rep := parse(t, res.RawOutput)
	if len(rep.Assets) == 0 {
		t.Fatal("the finished target's results were dropped")
	}
	if got := failedTargetValues(t, rep.Properties[unfinishedTargetsKey]); !slices.Equal(got, targets[1:]) {
		t.Fatalf("unfinished_targets %v", got)
	}
	if rep.Metadata.CoverageType != "partial" || res.Error == "" {
		t.Fatalf("coverage %q error %q", rep.Metadata.CoverageType, res.Error)
	}

	cctx, ccancel := context.WithCancel(context.Background())
	go func() { time.Sleep(time.Second); ccancel() }()
	if _, err := slowHTTPX(t, "30").ScanTargets(cctx, targets, nil); err == nil {
		t.Fatal("a canceled run delivered a result")
	}
}

// failedTargetValues reads a report's target list property: a list of
// target names or of {target, error}.
func failedTargetValues(t *testing.T, v any) []string {
	t.Helper()
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		switch x := e.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			s, _ := x["target"].(string)
			out = append(out, s)
		}
	}
	return out
}
