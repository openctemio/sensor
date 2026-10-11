package nuclei

import (
	"context"
	"strconv"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
)

// nuclei's flags carry the ceiling (the lowest limit) and the bounds
// table's per-host error budget.
func TestArgsCarryTheCeilingAndHostErrorBudget(t *testing.T) {
	s := NewScanner()
	s.Limits = Limits{MaxRateLimit: 100}
	cases := []struct {
		name string
		rate int
		want string
	}{
		{"scan asks more than the sensor ceiling", 500, "100"},
		{"scan asks less", 20, "20"},
		{"scan sets nothing", 0, strconv.Itoa(min(DefaultRateLimit, 100))},
	}
	for _, tc := range cases {
		args := s.buildArgs("https://h.example.test", &core.ScanOptions{RateLimit: tc.rate})
		if got := argValue(args, "-rate-limit"); got != tc.want {
			t.Errorf("%s: -rate-limit %s, want %s", tc.name, got, tc.want)
		}
		if got := argValue(args, "-mhe"); got != strconv.Itoa(adapt.TargetRate.ToolHostErrors) {
			t.Errorf("%s: -mhe %s, want %d", tc.name, got, adapt.TargetRate.ToolHostErrors)
		}
	}
}

// SECURITY (RFC-040): the sensor-local policy's rate.max_rps lower than the
// platform's rate_limit wins, all the way to nuclei's flag: the platform
// can only lower a local limit, never widen it.
func TestLocalPolicyLowerThanThePlatform(t *testing.T) {
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\nrate:\n  max_rps: 20\n"), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	platform := 500
	opts := &core.ScanOptions{RateLimit: lp.CapRate(platform)} // as the command executor does
	s := NewScanner()
	s.Limits = Limits{MaxRateLimit: 1000}
	if got := argValue(s.buildArgs("https://h.example.test", opts), "-rate-limit"); got != "20" {
		t.Fatalf("-rate-limit %s, want the local maximum 20", got)
	}
	rate, _, _ := s.EffectiveLimits(opts)
	if c := adapt.Ceiling(float64(platform), float64(rate)); c != 20 {
		t.Fatalf("forwarder ceiling %v, want 20", c)
	}
}

func TestCoverageGapsFromNucleiLog(t *testing.T) {
	stderr := "[INF] Templates loaded for current scan: 4000\n" +
		"[INF] Skipped a.example.test:443 from target list as found unresponsive 30 times\n" +
		"[INF] Skipped a.example.test:443 from target list as found unresponsive 30 times\n" +
		"[INF] Skipped b.example.test:80 from target list as found unresponsive permanently: no address found for host\n"
	gaps, total := coverageGaps(stderr)
	if total != 2 || len(gaps) != 2 {
		t.Fatalf("gaps %+v total %d, want 2", gaps, total)
	}
	if gaps[0].Host != "a.example.test:443" || gaps[0].Reason != adapt.GapBreakerOpen || gaps[1].Detail == gaps[0].Detail {
		t.Fatalf("gaps %+v", gaps)
	}
	if g, n := coverageGaps("[INF] scan done\n"); g != nil || n != 0 {
		t.Fatalf("gaps without skipped hosts: %+v", g)
	}
}

// A run in which nuclei skipped a host completes (not failed), and its
// result lists the host as a coverage gap.
func TestRunReportsSkippedHostsAsGaps(t *testing.T) {
	s := NewScanner()
	s.Binary = stubNucleiRun(t, "", "[INF] Skipped h.example.test:443 from target list as found unresponsive 30 times\n", 0)
	res, err := s.run(context.Background(), []string{"-u", "https://h.example.test"}, nil, nil, "h.example.test")
	if err != nil {
		t.Fatalf("a run with an unresponsive host failed: %v", err)
	}
	if !res.HasCoverageGaps() || res.CoverageGaps[0].Host != "h.example.test:443" {
		t.Fatalf("gaps %+v", res.CoverageGaps)
	}
}

func TestMergeResultsKeepsEveryGap(t *testing.T) {
	a := &core.ScanResult{CoverageGaps: []adapt.Gap{{Host: "a", Reason: adapt.GapBreakerOpen}}, CoverageGapsTotal: 1}
	b := &core.ScanResult{CoverageGaps: []adapt.Gap{{Host: "a", Reason: adapt.GapBreakerOpen}, {Host: "b", Reason: adapt.GapBreakerOpen}}, CoverageGapsTotal: 2}
	m := mergeResults([]*core.ScanResult{a, b})
	if len(m.CoverageGaps) != 2 || m.CoverageGapsTotal != 2 || len(a.CoverageGaps) != 1 {
		t.Fatalf("merged %+v (%d); first result changed: %v", m.CoverageGaps, m.CoverageGapsTotal, a.CoverageGaps)
	}
}
