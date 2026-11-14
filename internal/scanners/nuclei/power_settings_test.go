package nuclei

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func layered(t *testing.T, layers ...core.SettingsLayer) *core.ToolSettings {
	t.Helper()
	ts, err := NewScanner().SettingsSchema().Resolve(layers...)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return ts
}

func argsFor(t *testing.T, s *Scanner, ts *core.ToolSettings, opts *core.ScanOptions) []string {
	t.Helper()
	if opts == nil {
		opts = &core.ScanOptions{}
	}
	opts.Settings = ts
	sc, err := s.forScan(opts)
	if err != nil {
		t.Fatal(err)
	}
	return sc.buildArgs("https://example.com", opts)
}

// Every option the manifest names a native flag for reaches nuclei as that
// flag: the manifest and the argv cannot drift.
func TestManifestFlagsReachTheArgv(t *testing.T) {
	values := map[string]any{
		"rate_limit": 100, "concurrency": 10, "bulk_size": 5, "timeout": 7,
		"retries": 0, "max_host_errors": 9, "scan_strategy": "host-spray",
	}
	args := argsFor(t, NewScanner(), layered(t, core.SettingsLayer{Source: core.SettingSourceSensor, Values: values}), nil)
	want := map[string]string{"-rate-limit": "100", "-c": "10", "-bs": "5", "-timeout": "7", "-retries": "0", "-mhe": "9", "-ss": "host-spray"}
	schema := NewScanner().SettingsSchema()
	for _, p := range schema.Properties {
		if p.Flag == "" || p.Name == "tags" || p.Name == "exclude_tags" || p.Name == "severity" {
			continue
		}
		if got := settingFlag(args, p.Flag); got != want[p.Flag] {
			t.Errorf("%s (%s) = %q, want %q in %v", p.Name, p.Flag, got, want[p.Flag], args)
		}
	}
}

// The sensor's settings may raise the rate; the command's raw limit then
// no longer applies (the executor fitted it into the settings), and the
// operator's explicit ceiling still caps. The executor names the key the
// sensor's layer set (ScanOptions.ChosenSettings), so the job's cap under
// it is not mistaken for a default.
func TestSettingsLimitsReplaceTheCommandLimits(t *testing.T) {
	ts := layered(t,
		core.SettingsLayer{Source: core.SettingSourceSensor, Values: map[string]any{"rate_limit": 600}},
		core.SettingsLayer{Source: core.SettingSourceJob, Values: map[string]any{"rate_limit": 400}},
	)
	chosen := []string{"rate_limit"}
	args := argsFor(t, NewScanner(), ts, &core.ScanOptions{RateLimit: 900, ChosenSettings: chosen})
	if got := settingFlag(args, "-rate-limit"); got != "400" {
		t.Fatalf("-rate-limit %s, want the resolved 400", got)
	}
	s := NewScanner()
	s.Limits = Limits{MaxRateLimit: 300}
	if got := settingFlag(argsFor(t, s, ts, &core.ScanOptions{ChosenSettings: chosen}), "-rate-limit"); got != "300" {
		t.Fatalf("operator ceiling: -rate-limit %s", got)
	}
	// The same job cap with no person's choice under it: the level.
	jobOnly := layered(t, core.SettingsLayer{Source: core.SettingSourceJob, Values: map[string]any{"rate_limit": 100}})
	if got := settingFlag(argsFor(t, NewScanner(), jobOnly, nil), "-rate-limit"); got != "20" {
		t.Fatalf("job cap over the level: -rate-limit %s, want 20", got)
	}
}

// Without settings a one-host run gets the Standard level: 20/s, 8 in
// flight, 1 host per template, -mhe 15, -timeout 10, -retries 1, no -ss.
func TestNoSettingsRunsTheStandardLevel(t *testing.T) {
	args := NewScanner().buildArgs("https://example.com", &core.ScanOptions{RateLimit: 900})
	want := map[string]string{"-rate-limit": "20", "-c": "8", "-bs": "1", "-mhe": "15", "-timeout": "10", "-retries": "1"}
	for f, v := range want {
		if got := settingFlag(args, f); got != v {
			t.Errorf("%s %s, want %s", f, got, v)
		}
	}
	if slices.Contains(args, "-ss") {
		t.Fatalf("-ss on a one-host run: %v", args)
	}
}

// A scan may lower the performance options, never raise them above the
// default: that is the sensor's settings' decision.
func TestScanCannotRaisePerformance(t *testing.T) {
	schema := NewScanner().SettingsSchema()
	for _, v := range []map[string]any{{"rate_limit": 151}, {"concurrency": 26}, {"retries": 2}} {
		if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("scan raised %v", v)
		}
	}
	if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"bulk_size": 10}}); err == nil {
		t.Error("scan set the sensor-scope bulk_size")
	}
	if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"rate_limit": 50, "timeout": 30}}); err != nil {
		t.Errorf("scan lowering the rate and lengthening the timeout: %v", err)
	}
}
