package trivy

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// trivy's own 5-minute limit no longer cuts a run short: it gets the run's
// bound, and it makes no calls home on a scan.
func TestArgsCarryTheRunBoundAndNoPhoneHome(t *testing.T) {
	s := NewScanner()
	got := s.buildArgs("/src", nil)
	if i := slices.Index(got, "--timeout"); i < 0 || got[i+1] != DefaultTimeout.String() {
		t.Fatalf("--timeout: %q", got)
	}
	for _, f := range []string{"--disable-telemetry", "--skip-version-check"} {
		if !slices.Contains(got, f) {
			t.Errorf("%s missing: %q", f, got)
		}
	}
	if slices.Contains(got, "--skip-check-update") || slices.Contains(got, "--parallel") {
		t.Errorf("unmanaged database or no setting: %q", got)
	}

	s.Timeout, s.SkipDBUpdate = 2*time.Hour, true
	got = s.buildArgs("/src", nil)
	if i := slices.Index(got, "--timeout"); i < 0 || got[i+1] != "2h0m0s" {
		t.Fatalf("--timeout: %q", got)
	}
	if !slices.Contains(got, "--skip-check-update") {
		t.Errorf("managed database fetches checks: %q", got)
	}
}

// parallel is a sensor setting: the sensor's configuration sets it, a scan
// may not.
func TestParallelIsTheSensorsSetting(t *testing.T) {
	ts, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: map[string]any{"parallel": 0}})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner().withSettings(ts)
	if err != nil {
		t.Fatal(err)
	}
	if got := sc.buildArgs("/src", nil); !slices.Contains(got, "--parallel") || got[slices.Index(got, "--parallel")+1] != "0" {
		t.Fatalf("--parallel: %q", got)
	}
	if _, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"parallel": 8}}); err == nil {
		t.Fatal("a scan set the sensor's parallel")
	}
}
