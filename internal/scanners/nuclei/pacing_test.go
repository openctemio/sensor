package nuclei

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// forwarderEnforces fixes whether the task's forwarder holds each host to the budget
// (toolrun.PerHostEnforced depends on the host's sandbox otherwise).
func forwarderEnforces(t *testing.T, v bool) {
	t.Helper()
	toolrun.SetPerHostEnforced(&v)
	t.Cleanup(func() { toolrun.SetPerHostEnforced(nil) })
}

func budgetOf(t *testing.T, job adapt.JobBudget) adapt.HostBudget {
	t.Helper()
	if err := job.Validate(); err != nil {
		t.Fatal(err)
	}
	return adapt.ResolveBudget(adapt.DefaultPacing, &job, adapt.BudgetCeiling{})
}

// wideBudget is the widest budget a job can get (the hard ceiling), for
// tests of the settings layers and the operator's ceilings: with it and
// eight hosts under an enforcing forwarder the budget lowers nothing they
// assert.
func wideBudget(t *testing.T) adapt.HostBudget {
	return budgetOf(t, adapt.JobBudget{Level: "custom", RPS: 200, Inflight: 50})
}

func flagsOf(args []string) map[string]string {
	return map[string]string{
		"-rate-limit": settingFlag(args, "-rate-limit"), "-c": settingFlag(args, "-c"),
		"-bs": settingFlag(args, "-bs"), "-mhe": settingFlag(args, "-mhe"), "-ss": settingFlag(args, "-ss"),
		"-retries": settingFlag(args, "-retries"),
	}
}

// The host budget mapped to nuclei's command line for the run's host
// count. Under an enforcing forwarder: the per-host rate times the hosts
// worked at once (at most 8 at Standard and Fast, 4 at Gentle, and never
// above nuclei's ceiling of 150), the budget's requests in flight, hosts per
// template, the level's host error budget, template-spray over several
// hosts. Without one (an unconfined run): one host's budget for the whole
// run, whatever the host count.
func TestBudgetFlagsByHostCount(t *testing.T) {
	std := adapt.DefaultBudget()
	gentle := budgetOf(t, adapt.JobBudget{Level: "gentle"})
	fast := budgetOf(t, adapt.JobBudget{Level: "fast"})
	custom := budgetOf(t, adapt.JobBudget{RPS: 3, Inflight: 1})
	for _, tc := range []struct {
		name             string
		budget           adapt.HostBudget
		enforced         bool
		hosts            int
		rate, c, bs, mhe string
		ss               string
	}{
		{"standard", std, true, 1, "20", "8", "1", "15", ""},
		{"standard", std, true, 2, "40", "8", "2", "15", "template-spray"},
		{"standard", std, true, 7, "140", "8", "7", "15", "template-spray"},
		{"standard", std, true, 8, "150", "8", "8", "15", "template-spray"},
		{"standard", std, true, 40, "150", "8", "25", "15", "template-spray"},
		{"standard, unconfined", std, false, 1, "20", "8", "1", "15", ""},
		{"standard, unconfined", std, false, 2, "20", "8", "2", "15", "template-spray"},
		{"standard, unconfined", std, false, 40, "20", "8", "25", "15", "template-spray"},
		{"gentle", gentle, true, 1, "5", "2", "1", "10", ""},
		{"gentle", gentle, true, 10, "20", "2", "10", "10", "template-spray"},
		{"gentle, unconfined", gentle, false, 10, "5", "2", "10", "10", "template-spray"},
		{"fast", fast, true, 1, "100", "25", "1", "30", ""},
		{"fast", fast, true, 3, "150", "25", "3", "30", "template-spray"},
		{"fast, unconfined", fast, false, 3, "100", "25", "3", "30", "template-spray"},
		{"custom 3/s and 1 in flight", custom, true, 1, "3", "1", "1", "10", ""},
		{"custom 3/s and 1 in flight", custom, true, 2, "6", "1", "2", "10", "template-spray"},
	} {
		s := NewScanner()
		s.jobHosts = tc.hosts
		s.budget = runBudget{Budget: tc.budget, Enforced: tc.enforced}
		got := flagsOf(s.buildArgs("", nil))
		want := map[string]string{"-rate-limit": tc.rate, "-c": tc.c, "-bs": tc.bs, "-mhe": tc.mhe, "-ss": tc.ss, "-retries": "1"}
		for f := range want {
			if got[f] != want[f] {
				t.Errorf("%s, %d hosts: %s %q, want %q", tc.name, tc.hosts, f, got[f], want[f])
			}
		}
	}
	// A scanner no scan configured runs under the default budget.
	if got := flagsOf(NewScanner().buildArgs("", nil)); got["-rate-limit"] != "20" || got["-c"] != "8" {
		t.Errorf("no budget set: %v", got)
	}
}

// Caps below the level win: the operator's ceiling, the local policy's cap
// (reaching the scan's rate) and a job's cap in the settings.
func TestPacingNeverAboveACap(t *testing.T) {
	s := NewScanner()
	s.Limits = Limits{MaxRateLimit: 10, MaxConcurrency: 3}
	args := s.buildArgs("https://h.example.com", nil)
	if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != "10" || c != "3" {
		t.Errorf("operator ceiling: rate %s c %s, want 10 3", r, c)
	}
	args = NewScanner().buildArgs("https://h.example.com", &core.ScanOptions{RateLimit: 5})
	if r := settingFlag(args, "-rate-limit"); r != "5" {
		t.Errorf("local policy cap: rate %s, want 5", r)
	}
	ts := layered(t, core.SettingsLayer{Source: core.SettingSourceJob, Values: map[string]any{"rate_limit": 7, "timeout": 4}})
	args = argsFor(t, NewScanner(), ts, nil)
	if r, to := settingFlag(args, "-rate-limit"), settingFlag(args, "-timeout"); r != "7" || to != "4" {
		t.Errorf("job cap: rate %s timeout %s, want 7 4", r, to)
	}
}

// A value a person chose still replaces the level's for -bs, -mhe,
// -timeout and -ss, and a chosen rate or concurrency below the budget
// stays; above it, it is lowered to the budget. SECURITY: no settings
// layer raises what one host gets; only the job's signed budget and the
// sensor's own level do, under the operator's ceilings.
func TestBudgetBoundsChosenValues(t *testing.T) {
	forwarderEnforces(t, true)
	values := map[string]any{
		"rate_limit": 120, "concurrency": 20, "bulk_size": 10, "max_host_errors": 40,
		"timeout": 30, "scan_strategy": "host-spray",
	}
	ts := layered(t, core.SettingsLayer{Source: core.SettingSourceSensor, Values: values})
	s := NewScanner()
	s.jobHosts = 3
	// Standard over three hosts: 60/s in all, 8 in flight per host.
	args := argsFor(t, s, ts, nil)
	want := map[string]string{"-rate-limit": "60", "-c": "8", "-bs": "10", "-mhe": "40", "-timeout": "30", "-ss": "host-spray"}
	for f, v := range want {
		if got := settingFlag(args, f); got != v {
			t.Errorf("standard: %s %s, want %s", f, got, v)
		}
	}
	// A signed Fast budget: the chosen 120/s and 20 are below it and stay.
	args = argsFor(t, s, ts, &core.ScanOptions{HostBudget: budgetOf(t, adapt.JobBudget{Level: "fast"})})
	if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != "120" || c != "20" {
		t.Errorf("fast: rate %s c %s, want the chosen 120 20", r, c)
	}
	// "auto" chosen: nuclei's own strategy, no -ss even over several hosts.
	auto := layered(t, core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"scan_strategy": "auto"}})
	if args := argsFor(t, s, auto, nil); slices.Contains(args, "-ss") {
		t.Errorf("chosen auto passed -ss: %v", args)
	}

	// SECURITY: a tenant's raised rate never passes the host budget, nor
	// the operator's ceiling.
	tenant := layered(t, core.SettingsLayer{Source: core.SettingSourceTenant, Values: map[string]any{"rate_limit": 5000, "concurrency": 200}})
	capped := NewScanner()
	capped.Limits = Limits{MaxRateLimit: 200, MaxConcurrency: 50}
	chosen := []string{"rate_limit", "concurrency"}
	for _, tc := range []struct {
		name    string
		budget  adapt.HostBudget
		rate, c string
	}{
		{"no signed budget: Standard", adapt.HostBudget{}, "20", "8"},
		{"signed Gentle", budgetOf(t, adapt.JobBudget{Level: "gentle"}), "5", "2"},
		{"signed Fast", budgetOf(t, adapt.JobBudget{Level: "fast"}), "100", "25"},
		{"a signed budget above every ceiling", budgetOf(t, adapt.JobBudget{Level: "custom", RPS: 90000, Inflight: 9000}), "200", "50"},
	} {
		args = argsFor(t, capped, tenant, &core.ScanOptions{ChosenSettings: chosen, HostBudget: tc.budget})
		if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != tc.rate || c != tc.c {
			t.Errorf("tenant asks 5000/200, %s: rate %s c %s, want %s %s", tc.name, r, c, tc.rate, tc.c)
		}
	}
}

// The operator's scanner config (the registry's rate and concurrency) is
// bounded by the host budget as well; under a budget above it, it stands.
func TestBudgetBoundsOperatorConfig(t *testing.T) {
	s := NewScanner()
	s.RateLimit, s.Concurrency = 60, 12
	s.ChooseLimits(true, true)
	args := s.buildArgs("https://h.example.com", nil)
	if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != "20" || c != "8" {
		t.Errorf("standard: rate %s c %s, want 20 8", r, c)
	}
	s.budget = runBudget{Budget: budgetOf(t, adapt.JobBudget{Level: "fast"})}
	args = s.buildArgs("https://h.example.com", nil)
	if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != "60" || c != "12" {
		t.Errorf("fast: rate %s c %s, want 60 12", r, c)
	}
}

// The choices and the budget reach the tool child with the task: an
// out-of-process run paces exactly as an in-process one.
func TestPacingChoicesReachTheChild(t *testing.T) {
	in := appliedSettings{Limits: true, Chosen: chosenLimits{Rate: true, Strategy: true},
		Budget: runBudget{Budget: budgetOf(t, adapt.JobBudget{Level: "gentle"}), Enforced: true}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out appliedSettings
	if err := json.Unmarshal(raw, &out); err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip %s -> %+v (%v)", raw, out, err)
	}
	none, _ := json.Marshal(appliedSettings{})
	if string(none) != "{}" {
		t.Fatalf("empty applied settings %s", none)
	}
}

func TestDistinctHosts(t *testing.T) {
	for _, tc := range []struct {
		targets []string
		want    int
	}{
		{nil, 0},
		{[]string{"https://a.example.com/x", "https://a.example.com/y"}, 1},
		{[]string{"https://a.example.com", "http://b.example.com:8080", "192.0.2.10"}, 3},
	} {
		if got := distinctHosts(tc.targets); got != tc.want {
			t.Errorf("distinctHosts(%v) = %d, want %d", tc.targets, got, tc.want)
		}
		s := NewScanner().forTargets(tc.targets)
		if got := s.hosts(); got != max(tc.want, 1) {
			t.Errorf("hosts() = %d, want %s", got, strconv.Itoa(max(tc.want, 1)))
		}
	}
}
