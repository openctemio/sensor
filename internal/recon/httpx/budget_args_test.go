package httpx

import (
	"reflect"
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
// list of many hosts the level's sweep values; an unconfined run gets one
// host's budget, whatever its list.
func TestBudgetOnTheCommandLine(t *testing.T) {
	std := adapt.DefaultBudget()
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	fast := adapt.ResolveBudget(adapt.PacingFast, nil, adapt.BudgetCeiling{})
	for _, tc := range []struct {
		name        string
		budget      adapt.HostBudget
		hosts       int
		enforced    bool
		rl, threads string
	}{
		// The default probes cost one host two requests per target behind
		// the forwarder (the request and the favicon), and sixteen
		// connections where httpx dials itself (a JARM fingerprint too): -rl
		// is in targets a second.
		{"standard, one host, 500 URLs", std, 1, true, "10", "8"},
		{"standard, two hosts", std, 2, true, "20", "16"},
		{"standard, 1000 hosts", std, 1000, true, "50", "25"},
		// Without a forwarder nothing counts the names of a list that are
		// one server: the whole run gets one host's budget.
		{"standard, 1000 hosts, unconfined", std, 1000, false, "1", "8"},
		{"standard, 30 hosts, unconfined", std, 30, false, "1", "8"},
		{"gentle, one host", gentle, 1, true, "2", "2"},
		{"gentle, 1000 hosts", gentle, 1000, true, "15", "10"},
		{"fast, one host", fast, 1, true, "50", "25"},
		{"fast, 1000 hosts: the tool's own 150 and 50", fast, 1000, true, "150", "50"},
	} {
		s := NewScanner()
		rate, threads, _ := s.PacedLimits(tc.budget, tc.hosts, tc.enforced).Fit(nil, s.RateLimit, s.Threads)
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
	rate, threads, clamps := s.PacedLimits(std, 1, true).Fit(nil, s.RateLimit, s.Threads)
	if rate != 10 || threads != 8 {
		t.Errorf("operator config 120/40 on one host: %d/%d, want 10/8", rate, threads)
	}
	// What was asked and what applies is recorded, for both values.
	want := []adapt.BudgetClamp{{Key: "rate_limit", Asked: 120, To: 10, By: adapt.LimitHostBudget}, {Key: "threads", Asked: 40, To: 8, By: adapt.LimitHostBudget}}
	if !reflect.DeepEqual(clamps, want) {
		t.Errorf("clamps %+v, want %+v", clamps, want)
	}
	// The tool's own default that was paced is not a clamp.
	if _, _, clamps := NewScanner().PacedLimits(std, 1, true).Fit(nil, 150, 50); len(clamps) != 0 {
		t.Errorf("a paced default was recorded as a clamp: %+v", clamps)
	}
}

// What one target costs its host follows the probes that are on: -rl is in
// targets a second, and the host's budget is in requests.
func TestRateFollowsTheRequestsEachTargetCosts(t *testing.T) {
	std := adapt.DefaultBudget()
	for _, tc := range []struct {
		name          string
		favicon, jarm bool
		enforced      bool
		cost, rate    int
	}{
		{"the request alone", false, false, true, 1, 20},
		{"with the favicon", true, false, true, 2, 10},
		{"JARM is not asked behind the forwarder", true, true, true, 2, 10},
		{"JARM where httpx dials itself: fourteen connections more", true, true, false, 16, 1},
		{"JARM alone, unconfined", false, true, false, 15, 1},
	} {
		s := NewScanner()
		s.Favicon, s.Jarm = tc.favicon, tc.jarm
		if got := s.requestsPerTarget(tc.enforced); got != tc.cost {
			t.Errorf("%s: %d requests per target, want %d", tc.name, got, tc.cost)
		}
		if got := s.PacedLimits(std, 1, tc.enforced).Rate; got != tc.rate {
			t.Errorf("%s: -rl %d, want %d", tc.name, got, tc.rate)
		}
	}
}
