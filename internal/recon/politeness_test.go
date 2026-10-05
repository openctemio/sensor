package recon

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/naabu"
)

// limitRecon is a real tool type (for toolLimits) whose runs are recorded
// and answered from results.
type limitRecon struct {
	*httpx.Scanner
	results map[string]*core.ReconResult
	opts    []core.ReconOptions
}

func (f *limitRecon) Scan(_ context.Context, target string, o *core.ReconOptions) (*core.ReconResult, error) {
	f.opts = append(f.opts, *o)
	if r, ok := f.results[target]; ok {
		return r, nil
	}
	return &core.ReconResult{ScannerName: "httpx", ReconType: core.ReconTypeHTTPProbe, Target: target}, nil
}

func noSleep(t *testing.T) *[]int {
	t.Helper()
	old := sleepFn
	var waits []int
	sleepFn = func(_ context.Context, b *backoff) error { waits = append(waits, int(b.wait.Seconds())); return nil }
	t.Cleanup(func() { sleepFn = old })
	return &waits
}

// A scan's rate_limit and concurrency (capped by the local policy before
// they get here) lower the tool's limits and never raise them. Before, the
// wrapper dropped them and recon ran at the tools' defaults.
func TestScanTargets_RateLimitsOnlyLower(t *testing.T) {
	noSleep(t)
	for _, c := range []struct {
		req, conc       int
		wantRate, wantT int
	}{
		{0, 0, httpx.DefaultRateLimit, httpx.DefaultThreads},
		{10, 5, 10, 5},
		{100000, 100000, httpx.DefaultRateLimit, httpx.DefaultThreads},
	} {
		f := &limitRecon{Scanner: httpx.NewScanner()}
		if _, err := NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com"}, &core.ScanOptions{RateLimit: c.req, Concurrency: c.conc}); err != nil {
			t.Fatal(err)
		}
		if o := f.opts[0]; o.RateLimit != c.wantRate || o.Threads != c.wantT {
			t.Errorf("asked %d/%d: ran at rate %d threads %d, want %d/%d", c.req, c.conc, o.RateLimit, o.Threads, c.wantRate, c.wantT)
		}
	}
	// naabu (packets per second) is lowered the same way.
	if r, _ := toolLimits(naabu.NewScanner()); lower(r, 50) != 50 || lower(r, 1e6) != naabu.DefaultRate {
		t.Errorf("naabu limits: own %d", r)
	}
}

// A target answering 429 halves the rate of the job's later targets, waits
// with a growing backoff, and is reported as throttled.
func TestScanTargets_BackOffOn429(t *testing.T) {
	waits := noSleep(t)
	f := &limitRecon{Scanner: httpx.NewScanner(), results: map[string]*core.ReconResult{
		"a.example.com": {LiveHosts: []core.LiveHost{{URL: "https://a.example.com", Host: "a.example.com", StatusCode: 429}}},
		"b.example.com": {LiveHosts: []core.LiveHost{{URL: "https://b.example.com", Host: "b.example.com", StatusCode: 503}}},
	}}
	res, err := NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com", "b.example.com", "c.example.com"}, &core.ScanOptions{RateLimit: 40})
	if err != nil {
		t.Fatal(err)
	}
	var rates []int
	for _, o := range f.opts {
		rates = append(rates, o.RateLimit)
	}
	if !slices.Equal(rates, []int{40, 20, 10}) {
		t.Errorf("rates %v, want 40, 20, 10", rates)
	}
	if !slices.Equal(*waits, []int{2, 4}) {
		t.Errorf("waits %v, want 2s then 4s", *waits)
	}
	r := parse(t, res.RawOutput)
	if r.Properties["target_throttled"] != true {
		t.Errorf("target_throttled = %v", r.Properties["target_throttled"])
	}
	got, _ := r.Properties["throttled_targets"].([]any)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("throttled_targets = %v", r.Properties["throttled_targets"])
	}

	// No throttling: no wait, no property.
	*waits = nil
	f = &limitRecon{Scanner: httpx.NewScanner()}
	res, err = NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com", "b.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := parse(t, res.RawOutput); r.Properties["throttled_targets"] != nil || len(*waits) != 1 || (*waits)[0] != 0 {
		t.Errorf("unthrottled job: props %v waits %v", r.Properties, *waits)
	}
}

func TestBackoffFloorAndCap(t *testing.T) {
	var b backoff
	for range 20 {
		b.hit("x", 0)
	}
	if b.rate != 1 || b.wait != maxBackoff {
		t.Errorf("after 20 hits: rate %d wait %s", b.rate, b.wait)
	}
}

// SECURITY (negative): extra args cannot send a tool off the target's host,
// in any spelling; nothing runs.
func TestScanTargets_ExtraArgsStayOnTheHost(t *testing.T) {
	noSleep(t)
	for _, extra := range [][]string{
		{"-follow-redirects"}, {"-fr"}, {"--fr"}, {"-fs", "rdn"}, {"-field-scope=dn"},
		{"-cs", ".*"}, {"-ns"}, {"-no-scope"}, {"-dr=false"}, {" -Disable-Redirects=false"},
	} {
		f := &limitRecon{Scanner: httpx.NewScanner()}
		if _, err := NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com"}, &core.ScanOptions{ExtraArgs: extra}); err == nil || len(f.opts) != 0 {
			t.Errorf("extra args %q: err %v, runs %d", extra, err, len(f.opts))
		}
	}
	if err := checkHostBoundArgs([]string{"-mc", "fr"}); err != nil {
		t.Errorf("a value refused as a flag: %v", err)
	}
}
