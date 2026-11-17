package recon

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/toolrun"
)

// limitRecon is a real tool type (for toolLimits) whose runs are recorded
// and answered from results.
type limitRecon struct {
	*httpx.Scanner
	results map[string]*core.ReconResult
	opts    []core.ReconOptions
}

// Batchable: the double answers per target (it records each run's
// options), so it takes the per-target path, not httpx's batch run.
func (f *limitRecon) Batchable() bool { return false }

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
	off := false
	toolrun.SetPerHostEnforced(&off)
	t.Cleanup(func() { toolrun.SetPerHostEnforced(nil) })
	one := []string{"a.example.com"}
	// One host with many URLs, and a list of many hosts.
	sameHost := []string{"https://a.example.com/1", "https://a.example.com/2", "http://a.example.com:8080/3", "a.example.com"}
	var many []string
	for i := range 40 {
		many = append(many, "h"+strconv.Itoa(i)+".example.com")
	}
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	fast := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "fast"}, adapt.BudgetCeiling{})
	for _, c := range []struct {
		name            string
		targets         []string
		budget          adapt.HostBudget
		req, conc       int
		chosen          []string
		wantRate, wantT int
	}{
		// One host: that host's budget, whoever chose a value.
		{"one host", one, adapt.HostBudget{}, 0, 0, nil, 20, 8},
		{"one host, the scan asks less", one, adapt.HostBudget{}, 10, 5, nil, 10, 5},
		{"one host, the scan asks more", one, adapt.HostBudget{}, 100000, 100000, nil, 20, 8},
		{"one host, a person chose the tool's 150 and 50", one, adapt.HostBudget{}, 0, 0, []string{"rate_limit", "threads"}, 20, 8},
		{"many URLs of one host", sameHost, adapt.HostBudget{}, 0, 0, nil, 20, 8},
		// Many hosts: the sweep values (each host gets a request or two).
		{"forty hosts", many, adapt.HostBudget{}, 0, 0, nil, 50, 25},
		{"forty hosts, signed Gentle", many, gentle, 0, 0, nil, 15, 10},
		{"forty hosts, signed Fast", many, fast, 0, 0, nil, 150, 50},
		{"one host, signed Gentle", one, gentle, 0, 0, []string{"rate_limit"}, 5, 2},
		{"one host, signed Fast, the tool's own limits", one, fast, 0, 0, nil, 100, 25},
	} {
		f := &limitRecon{Scanner: httpx.NewScanner()}
		opts := &core.ScanOptions{RateLimit: c.req, Concurrency: c.conc, ChosenSettings: c.chosen, HostBudget: c.budget}
		if _, err := NewScanner(f).ScanTargets(t.Context(), c.targets, opts); err != nil {
			t.Fatal(err)
		}
		if o := f.opts[0]; o.RateLimit != c.wantRate || o.Threads != c.wantT {
			t.Errorf("%s: ran at rate %d threads %d, want %d/%d", c.name, o.RateLimit, o.Threads, c.wantRate, c.wantT)
		}
	}
	// naabu (packets per second) is lowered the same way.
	if r, _ := toolLimits(naabu.NewScanner()); lower(r, 50) != 50 || lower(r, 1e6) != naabu.DefaultRate {
		t.Errorf("naabu limits: own %d", r)
	}
}

// A target answering 429 halves the rate of the job's later targets, waits
// with a growing backoff.
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
	if len(r.Properties) != 0 {
		t.Errorf("throttling marks in the report's properties: %v", r.Properties)
	}

	// No throttling: no wait, no property.
	*waits = nil
	f = &limitRecon{Scanner: httpx.NewScanner()}
	res, err = NewScanner(f).ScanTargets(t.Context(), []string{"a.example.com", "b.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := parse(t, res.RawOutput); len(r.Properties) != 0 || len(*waits) != 1 || (*waits)[0] != 0 {
		t.Errorf("unthrottled job: props %v waits %v", r.Properties, *waits)
	}
}

func TestBackoffFloorAndCap(t *testing.T) {
	var b backoff
	for range 20 {
		b.hit("x", 0, 0)
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
