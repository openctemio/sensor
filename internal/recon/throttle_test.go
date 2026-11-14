package recon

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/recon/httpx"
)

func probe(host string, status int, retryAfter time.Duration) *core.ReconResult {
	return &core.ReconResult{ScannerName: "httpx", ReconType: core.ReconTypeHTTPProbe, Target: host,
		LiveHosts: []core.LiveHost{{URL: "https://" + host, Host: host, StatusCode: status, RetryAfter: retryAfter}}}
}

func targetState(r *ctis.Report, target string) (ctis.TargetState, ctis.TargetClass) {
	for _, o := range r.Metadata.Targets {
		if o.Target == target {
			return o.State, o.Class
		}
	}
	return "", ""
}

// A batch run over the whole list (httpx) cannot slow down part-way: every
// target that answered 429 or 503 is a "throttled" coverage gap with its
// counts, its outcome is rate limited, and its record is still kept.
func TestBatchRunMarksThrottledTargets(t *testing.T) {
	f := &fakeBatch{fakeRecon: fakeRecon{name: "httpx", typ: core.ReconTypeHTTPProbe, results: map[string]*core.ReconResult{
		"a.example.com": probe("a.example.com", 429, 0),
		"b.example.com": probe("b.example.com", 503, 0),
		"c.example.com": probe("c.example.com", 200, 0),
	}}}
	targets := []string{"a.example.com", "b.example.com", "c.example.com"}
	res, _, err := NewScanner(f).scanTargets(context.Background(), targets, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.batchCalls != 1 {
		t.Fatalf("batch calls %d, want 1", f.batchCalls)
	}
	want := []adapt.Gap{
		{Host: "a.example.com", Reason: adapt.GapThrottled, Detail: "429=1"},
		{Host: "b.example.com", Reason: adapt.GapThrottled, Detail: "503=1"},
	}
	if !slices.Equal(res.CoverageGaps, want) || res.CoverageGapsTotal != 2 {
		t.Fatalf("gaps %+v total %d, want %+v", res.CoverageGaps, res.CoverageGapsTotal, want)
	}
	r := parse(t, res.RawOutput)
	for _, tc := range []struct {
		target string
		state  ctis.TargetState
		class  ctis.TargetClass
	}{
		{"a.example.com", ctis.TargetFailed, ctis.TargetClassRateLimited},
		{"b.example.com", ctis.TargetFailed, ctis.TargetClassRateLimited},
		{"c.example.com", ctis.TargetDone, ""},
	} {
		if st, cl := targetState(r, tc.target); st != tc.state || cl != tc.class {
			t.Errorf("%s: %s/%s, want %s/%s", tc.target, st, cl, tc.state, tc.class)
		}
	}
	// Never dropped: the throttled targets' records are in the report.
	if len(r.Assets) == 0 {
		t.Fatal("no assets: the throttled records were dropped")
	}
	// The hand-over to the sensor stays off the sent report.
	if len(r.Properties) != 0 {
		t.Errorf("gaps in the report's properties: %v", r.Properties)
	}
}

// A serial run waits at least the target's Retry-After before the next one
// and reports the wait in the gap.
func TestSerialRunHonoursRetryAfter(t *testing.T) {
	waits := noSleep(t)
	f := &limitRecon{Scanner: httpx.NewScanner(), results: map[string]*core.ReconResult{
		"a.example.com": probe("a.example.com", 429, 20*time.Second),
	}}
	res, err := NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com", "b.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*waits, []int{20}) {
		t.Errorf("waits %v, want the Retry-After 20s", *waits)
	}
	if len(res.CoverageGaps) != 1 || res.CoverageGaps[0].Detail != "429=1 retry_after=20s" {
		t.Errorf("gaps %+v", res.CoverageGaps)
	}
}

// No push-back: no gap, no wait, the run is unchanged.
func TestNoThrottleNoGap(t *testing.T) {
	f := &fakeBatch{fakeRecon: fakeRecon{name: "httpx", typ: core.ReconTypeHTTPProbe, results: map[string]*core.ReconResult{
		"a.example.com": probe("a.example.com", 200, 0),
		"b.example.com": probe("b.example.com", 403, 0),
	}}}
	res, _, err := NewScanner(f).scanTargets(context.Background(), []string{"a.example.com", "b.example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CoverageGaps) != 0 || res.CoverageGapsTotal != 0 {
		t.Fatalf("gaps %+v", res.CoverageGaps)
	}
}

func TestObserveThrottle(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *core.ReconResult
		want bool
	}{
		{"nil", nil, false},
		{"200", probe("a.example.com", 200, 0), false},
		{"429", probe("a.example.com", 429, 0), true},
		{"503", probe("a.example.com", 503, 0), true},
		{"200 with Retry-After", probe("a.example.com", 200, 5*time.Second), true},
		{"crawled URL 429", &core.ReconResult{URLs: []core.DiscoveredURL{{URL: "https://a.example.com/x", StatusCode: 429}}}, true},
	} {
		var tally adapt.ThrottleTally
		if got, _ := observeThrottle(&tally, "a.example.com", tc.r); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	// The Retry-After is this target's own, not the longest of the job.
	var tally adapt.ThrottleTally
	observeThrottle(&tally, "x.example.com", probe("x.example.com", 429, 4*time.Minute))
	if _, ra := observeThrottle(&tally, "a.example.com", probe("a.example.com", 429, 3*time.Second)); ra != 3*time.Second {
		t.Errorf("retry-after %s, want this target's 3s", ra)
	}
}

// One hostile target cannot hold up the others: its Retry-After of minutes
// becomes at most maxBackoff before the next target, and a target that
// answered normally lets the one after it start at once.
func TestSerialRunHostileRetryAfterBounded(t *testing.T) {
	waits := noSleep(t)
	f := &limitRecon{Scanner: httpx.NewScanner(), results: map[string]*core.ReconResult{
		"a.example.com": probe("a.example.com", 429, 5*time.Minute),
		"c.example.com": probe("c.example.com", 429, 0),
	}}
	targets := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}
	if _, err := NewScanner(f).ScanTargets(t.Context(), targets, nil); err != nil {
		t.Fatal(err)
	}
	want := []int{int(maxBackoff.Seconds()), 0, int(initialBackoff.Seconds()), 0}
	if !slices.Equal(*waits, want) {
		t.Fatalf("waits %v, want %v", *waits, want)
	}
	for _, w := range *waits {
		if time.Duration(w)*time.Second > maxBackoff {
			t.Fatalf("a wait of %ds is past the bound %s", w, maxBackoff)
		}
	}
}
