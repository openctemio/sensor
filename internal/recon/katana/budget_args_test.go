package katana

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
)

func budgetFlag(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// The host budget on katana's command line: -rl and -c. A crawl works each
// origin for long, so it gets the budget for each host it crawls at once
// under an enforcing forwarder, and one host's budget for the whole run
// without one.
func TestBudgetOnTheCommandLine(t *testing.T) {
	std := adapt.DefaultBudget()
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	fast := adapt.ResolveBudget(adapt.PacingFast, nil, adapt.BudgetCeiling{})
	for _, tc := range []struct {
		name     string
		budget   adapt.HostBudget
		hosts    int
		enforced bool
		rl, c    string
	}{
		{"standard, one host", std, 1, true, "20", "8"},
		{"standard, three hosts", std, 3, true, "60", "10"},
		{"standard, three hosts, unconfined", std, 3, false, "20", "8"},
		{"gentle, one host", gentle, 1, true, "5", "2"},
		{"fast, one host: the tool's own 10 workers", fast, 1, true, "100", "10"},
		{"fast, three hosts: the tool's own 150 and 10", fast, 3, true, "150", "10"},
	} {
		s := NewScanner()
		rate, conc, _ := s.PacedLimits(tc.budget, tc.hosts, tc.enforced).Fit(nil, s.RateLimit, s.Concurrency)
		args := s.buildArgs("https://a.example.com", &core.ReconOptions{RateLimit: rate, Threads: conc})
		if rl, c := budgetFlag(args, "-rl"), budgetFlag(args, "-c"); rl != tc.rl || c != tc.c {
			t.Errorf("%s: -rl %s -c %s, want %s %s", tc.name, rl, c, tc.rl, tc.c)
		}
	}
	// The operator's own config above the budget is lowered to it too.
	s := NewScanner()
	s.RateLimit, s.Concurrency = 90, 30
	s.ChooseLimits(true, true)
	rate, conc, clamps := s.PacedLimits(std, 1, true).Fit(nil, s.RateLimit, s.Concurrency)
	if rate != 20 || conc != 8 {
		t.Errorf("operator config 90/30 on one host: %d/%d, want 20/8", rate, conc)
	}
	// What was asked and what applies is recorded, for both values.
	if len(clamps) != 2 || clamps[0] != (adapt.BudgetClamp{Key: "rate_limit", Asked: 90, To: 20, By: adapt.LimitHostBudget}) ||
		clamps[1] != (adapt.BudgetClamp{Key: "concurrency", Asked: 30, To: 8, By: adapt.LimitHostBudget}) {
		t.Errorf("clamps %+v", clamps)
	}
}
