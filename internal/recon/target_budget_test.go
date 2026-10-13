package recon

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// The platform's per-target budget becomes each target's run timeout when
// it is shorter than the configured one; it never lengthens it.
func TestTargetTimeout(t *testing.T) {
	budget := &core.ScanOptions{TargetTimeout: 15 * time.Second}
	cases := []struct {
		configured time.Duration
		opts       *core.ScanOptions
		want       time.Duration
	}{
		{0, nil, 0},
		{0, budget, 15 * time.Second},
		{30 * time.Minute, budget, 15 * time.Second},
		{5 * time.Second, budget, 5 * time.Second},
		{30 * time.Minute, &core.ScanOptions{}, 30 * time.Minute},
	}
	for _, c := range cases {
		if got := targetTimeout(c.configured, c.opts); got != c.want {
			t.Errorf("targetTimeout(%s, %+v) = %s, want %s", c.configured, c.opts, got, c.want)
		}
	}
}

// Every recon run gets the per-target budget, and each settled target
// counts toward the job's progress.
func TestScanTargets_PerTargetBudgetAndProgress(t *testing.T) {
	f := &optsRecon{fakeRecon: fakeRecon{name: "httpx", typ: core.ReconTypeDNS}}
	prog := core.NewProgress(3)
	ctx := core.WithProgress(context.Background(), prog)
	targets := []string{"a.example.com", "b.example.com", "c.example.com"}
	if _, err := NewScanner(f).ScanTargets(ctx, targets, &core.ScanOptions{TargetTimeout: 15 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if len(f.opts) != 3 {
		t.Fatalf("runs = %d", len(f.opts))
	}
	for _, o := range f.opts {
		if o.Timeout != 15*time.Second {
			t.Fatalf("run timeout = %s, want the 15s target budget", o.Timeout)
		}
	}
	if got := prog.Snapshot(); got.Done != 3 || got.Total != 3 {
		t.Fatalf("progress %+v", got)
	}
}

// The budget reaches the tool child (the out-of-process path) intact.
func TestScanLocalCarriesTheTargetBudget(t *testing.T) {
	got := scanLocalOf(&core.ScanOptions{TargetTimeout: 1500 * time.Millisecond}).options()
	if got.TargetTimeout != 1500*time.Millisecond {
		t.Fatalf("TargetTimeout = %s", got.TargetTimeout)
	}
}
