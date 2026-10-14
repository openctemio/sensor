package recon

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// fakeBatch is a recon tool that scans a list in one run.
type fakeBatch struct {
	fakeRecon
	batchCalls int
	gotOpts    core.ReconOptions
	batchErr   error
	// cancel, when set, is called during the run (the job ends mid-run).
	cancel func()
}

func (f *fakeBatch) ScanBatch(_ context.Context, targets []string, opts *core.ReconOptions, _ time.Duration, _ func(string)) (map[string]*core.ReconResult, error) {
	f.batchCalls++
	f.gotOpts = *opts
	if f.cancel != nil {
		f.cancel()
	}
	out := map[string]*core.ReconResult{}
	for _, t := range targets {
		if r, ok := f.results[t]; ok {
			out[t] = r
		}
	}
	return out, f.batchErr
}

func portResult(host string, port int) *core.ReconResult {
	return &core.ReconResult{ScannerName: "naabu", ReconType: core.ReconTypePort, Target: host,
		OpenPorts: []core.OpenPort{{Host: host, Port: port, Protocol: "tcp"}}}
}

func TestBatchToolRunsTheListOnce(t *testing.T) {
	f := &fakeBatch{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort, results: map[string]*core.ReconResult{
		"a.example": portResult("a.example", 443),
		"b.example": portResult("b.example", 22),
	}}}
	var settled []string
	s := NewScanner(f)
	s.Options.Timeout = 30e9
	res, _, err := s.scanTargets(context.Background(), []string{"a.example", "silent.example", "b.example"},
		&core.ScanOptions{TargetTimeout: 5e9, Concurrency: 7}, func(i int, err error) {
			if err != nil {
				t.Errorf("target %d failed: %v", i, err)
			}
			settled = append(settled, []string{"a.example", "silent.example", "b.example"}[i])
		})
	if err != nil {
		t.Fatal(err)
	}
	if f.batchCalls != 1 || len(f.seen) != 0 {
		t.Fatalf("batch calls %d, per-target runs %v", f.batchCalls, f.seen)
	}
	// The per-target budget is not a kill in a batch; the job's
	// concurrency reaches the tool.
	if f.gotOpts.Timeout != 0 || f.gotOpts.Threads != 7 {
		t.Fatalf("batch options: timeout %s threads %d", f.gotOpts.Timeout, f.gotOpts.Threads)
	}
	// Every target is settled, the silent one too (no open port is an
	// outcome).
	if !slices.Equal(settled, []string{"a.example", "silent.example", "b.example"}) {
		t.Fatalf("settled %v", settled)
	}
	rep := parse(t, res.RawOutput)
	if len(rep.Assets) == 0 {
		t.Fatal("no assets")
	}
	if rep.Properties["failed_targets"] != nil {
		t.Fatalf("failed targets: %v", rep.Properties["failed_targets"])
	}
}

func TestBatchSingleTargetUsesTheTargetRun(t *testing.T) {
	f := &fakeBatch{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort}}
	if _, err := NewScanner(f).ScanTargets(context.Background(), []string{"a.example"}, nil); err != nil {
		t.Fatal(err)
	}
	if f.batchCalls != 0 || len(f.seen) != 1 {
		t.Fatalf("batch calls %d, per-target runs %v", f.batchCalls, f.seen)
	}
}

func TestBatchRunFailureFailsTheJob(t *testing.T) {
	f := &fakeBatch{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort}, batchErr: errors.New("exit 2: bad flag")}
	_, err := NewScanner(f).ScanTargets(context.Background(), []string{"a.example", "b.example"}, nil)
	if !errors.Is(err, ErrToolFailed) {
		t.Fatalf("err = %v, want ErrToolFailed", err)
	}
}

// A run failure after some records keeps those targets' results; the
// others fail on their own.
func TestBatchRunFailureKeepsReadRecords(t *testing.T) {
	f := &fakeBatch{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort, results: map[string]*core.ReconResult{
		"a.example": portResult("a.example", 443),
	}}, batchErr: errors.New("exit 1")}
	res, err := NewScanner(f).ScanTargets(context.Background(), []string{"a.example", "b.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep := parse(t, res.RawOutput)
	if got := failedTargetValues(t, rep.Properties["failed_targets"]); !slices.Equal(got, []string{"b.example"}) {
		t.Fatalf("failed targets %v", got)
	}
}

// The job ending mid-run keeps the targets with records and lists the
// others as unfinished.
func TestBatchStoppedRunKeepsSettledTargets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeBatch{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort, results: map[string]*core.ReconResult{
		"b.example": portResult("b.example", 443),
	}}, cancel: cancel}
	res, _, err := NewScanner(f).scanTargets(ctx, []string{"a.example", "b.example", "c.example"}, nil, nil)
	if err == nil {
		t.Fatal("a stopped run returned no error")
	}
	if res == nil {
		t.Fatal("the settled target's records were dropped")
	}
	rep := parse(t, res.RawOutput)
	if got := failedTargetValues(t, rep.Properties[unfinishedTargetsKey]); !slices.Equal(got, []string{"a.example", "c.example"}) {
		t.Fatalf("unfinished %v", got)
	}
	if rep.Metadata.CoverageType != "partial" {
		t.Fatalf("coverage %q", rep.Metadata.CoverageType)
	}
}
