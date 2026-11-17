package naabu

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
)

// A port scan is paced in packets per second, at the level of the scan's
// budget: -rate 300 at Standard, 100 at Gentle, 1000 at Fast. It is a
// default (a chosen rate replaces it), not the HTTP host budget, and it
// does not depend on the host count.
func TestProbeRateOnTheCommandLine(t *testing.T) {
	std := adapt.DefaultBudget()
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	fast := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "fast"}, adapt.BudgetCeiling{})
	rateFlag := func(args []string) string {
		if i := slices.Index(args, "-rate"); i >= 0 && i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	for _, tc := range []struct {
		name   string
		budget adapt.HostBudget
		hosts  int
		opts   *core.ScanOptions
		want   string
	}{
		{"standard", std, 1, nil, "300"},
		{"standard, many hosts, unconfined", std, 500, nil, "300"},
		{"gentle", gentle, 1, nil, "100"},
		{"fast", fast, 1, nil, "1000"},
		{"a chosen rate replaces the level's", gentle, 1, &core.ScanOptions{ChosenSettings: []string{"rate"}}, "1000"},
	} {
		s := NewScanner()
		pl := s.PacedLimits(tc.budget, tc.hosts, 1, false)
		if pl.Hard || pl.Concurrency != 0 {
			t.Fatalf("%s: naabu's packet rate is a default, not the host budget: %+v", tc.name, pl)
		}
		rate, _ := pl.Fit(tc.opts, s.Rate, 0)
		args := s.buildArgs("192.0.2.10", &core.ReconOptions{RateLimit: rate})
		if got := rateFlag(args); got != tc.want {
			t.Errorf("%s: -rate %s, want %s", tc.name, got, tc.want)
		}
	}
}
