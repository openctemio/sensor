package nuclei

import (
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// The Standard level mapped to nuclei's flags for the run's host count: the
// per-host rate times the hosts worked at once (at most 8, and never above
// the schema default 150), 8 in flight, hosts per template up to 25,
// template-spray over several hosts.
func TestPacingFlagsByHostCount(t *testing.T) {
	for _, tc := range []struct {
		hosts            int
		rate, c, bs, mhe string
		ss               string
	}{
		{1, "20", "8", "1", "15", ""},
		{2, "40", "8", "2", "15", "template-spray"},
		{7, "140", "8", "7", "15", "template-spray"},
		{8, "150", "8", "8", "15", "template-spray"},
		{40, "150", "8", "25", "15", "template-spray"},
	} {
		s := NewScanner()
		s.jobHosts = tc.hosts
		args := s.buildArgs("", nil)
		got := map[string]string{
			"-rate-limit": settingFlag(args, "-rate-limit"), "-c": settingFlag(args, "-c"),
			"-bs": settingFlag(args, "-bs"), "-mhe": settingFlag(args, "-mhe"), "-ss": settingFlag(args, "-ss"),
		}
		want := map[string]string{"-rate-limit": tc.rate, "-c": tc.c, "-bs": tc.bs, "-mhe": tc.mhe, "-ss": tc.ss}
		for f := range want {
			if got[f] != want[f] {
				t.Errorf("%d hosts: %s %q, want %q", tc.hosts, f, got[f], want[f])
			}
		}
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

// A value a person chose replaces the level's (still under the operator's
// ceiling); the threat model: a tenant can never exceed the operator's
// ceiling, whatever it sets.
func TestPacingChosenValues(t *testing.T) {
	values := map[string]any{
		"rate_limit": 120, "concurrency": 20, "bulk_size": 10, "max_host_errors": 40,
		"timeout": 30, "scan_strategy": "host-spray",
	}
	ts := layered(t, core.SettingsLayer{Source: core.SettingSourceSensor, Values: values})
	s := NewScanner()
	s.jobHosts = 3
	args := argsFor(t, s, ts, nil)
	want := map[string]string{"-rate-limit": "120", "-c": "20", "-bs": "10", "-mhe": "40", "-timeout": "30", "-ss": "host-spray"}
	for f, v := range want {
		if got := settingFlag(args, f); got != v {
			t.Errorf("%s %s, want %s", f, got, v)
		}
	}
	// "auto" chosen: nuclei's own strategy, no -ss even over several hosts.
	auto := layered(t, core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"scan_strategy": "auto"}})
	if args := argsFor(t, s, auto, nil); slices.Contains(args, "-ss") {
		t.Errorf("chosen auto passed -ss: %v", args)
	}

	// SECURITY: a tenant's raised rate is capped by the operator's ceiling.
	tenant := layered(t, core.SettingsLayer{Source: core.SettingSourceTenant, Values: map[string]any{"rate_limit": 5000, "concurrency": 200}})
	capped := NewScanner()
	capped.Limits = Limits{MaxRateLimit: 200, MaxConcurrency: 50}
	args = argsFor(t, capped, tenant, &core.ScanOptions{ChosenSettings: []string{"rate_limit", "concurrency"}})
	if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != "200" || c != "50" {
		t.Errorf("tenant above the operator ceiling: rate %s c %s, want 200 50", r, c)
	}
}

// The operator's scanner config (the registry's rate and concurrency) is a
// person's choice too.
func TestPacingOperatorConfigIsChosen(t *testing.T) {
	s := NewScanner()
	s.RateLimit, s.Concurrency = 60, 12
	s.ChooseLimits(true, true)
	args := s.buildArgs("https://h.example.com", nil)
	if r, c := settingFlag(args, "-rate-limit"), settingFlag(args, "-c"); r != "60" || c != "12" {
		t.Errorf("rate %s c %s, want 60 12", r, c)
	}
}

// The choices reach the tool child with the task: an out-of-process run
// paces exactly as an in-process one.
func TestPacingChoicesReachTheChild(t *testing.T) {
	in := appliedSettings{Limits: true, Chosen: chosenLimits{Rate: true, Strategy: true}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out appliedSettings
	if err := json.Unmarshal(raw, &out); err != nil || out != in {
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
