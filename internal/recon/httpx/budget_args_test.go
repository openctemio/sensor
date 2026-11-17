package httpx

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func flagOf(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// The host budget on httpx's command line: -rl and -threads for a run over
// the given hosts. A list of one host's URLs gets that host's budget; a
// list of many hosts the level's sweep values; an unconfined run whose
// list one host dominates gets one host's budget.
func TestBudgetOnTheCommandLine(t *testing.T) {
	std := adapt.DefaultBudget()
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	fast := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "fast"}, adapt.BudgetCeiling{})
	for _, tc := range []struct {
		name              string
		budget            adapt.HostBudget
		hosts, maxPerHost int
		enforced          bool
		rl, threads       string
	}{
		{"standard, one host, 500 URLs", std, 1, 500, true, "20", "8"},
		{"standard, two hosts", std, 2, 1, true, "40", "16"},
		{"standard, 1000 hosts", std, 1000, 1, true, "50", "25"},
		{"standard, 1000 hosts, unconfined", std, 1000, 2, false, "50", "25"},
		{"standard, unconfined, one host has 400 of the URLs", std, 30, 400, false, "20", "8"},
		{"gentle, one host", gentle, 1, 1, true, "5", "2"},
		{"gentle, 1000 hosts", gentle, 1000, 1, true, "15", "10"},
		{"fast, one host", fast, 1, 1, true, "100", "25"},
		{"fast, 1000 hosts: the tool's own 150 and 50", fast, 1000, 1, true, "150", "50"},
	} {
		s := NewScanner()
		rate, threads := s.PacedLimits(tc.budget, tc.hosts, tc.maxPerHost, tc.enforced).Fit(nil, s.RateLimit, s.Threads)
		args := s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/in.txt", RateLimit: rate, Threads: threads})
		if rl, th := flagOf(args, "-rl"), flagOf(args, "-threads"); rl != tc.rl || th != tc.threads {
			t.Errorf("%s: -rl %s -threads %s, want %s %s", tc.name, rl, th, tc.rl, tc.threads)
		}
		flagcheck.Check(t, helpFile, args)
	}
	// The operator's own config above the budget is lowered to it too.
	s := NewScanner()
	s.RateLimit, s.Threads = 120, 40
	s.ChooseLimits(true, true)
	rate, threads := s.PacedLimits(std, 1, 1, true).Fit(nil, s.RateLimit, s.Threads)
	if rate != 20 || threads != 8 {
		t.Errorf("operator config 120/40 on one host: %d/%d, want 20/8", rate, threads)
	}
}
