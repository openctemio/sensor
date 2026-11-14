package toolrun

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func TestChosenAndFit(t *testing.T) {
	schema := core.MustParseSettingsSchema(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 150, "x-octm-common": "rate", "x-octm-scope": "scan"},
    "threads": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50, "x-octm-common": "concurrency", "x-octm-scope": "scan"}
  }
}`)
	resolve := func(layers ...core.SettingsLayer) *core.ToolSettings {
		ts, err := schema.Resolve(layers...)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	pl := PacedLimits{RateKey: "rate_limit", Rate: 50, ConcurrencyKey: "threads", Concurrency: 25}
	for _, tc := range []struct {
		name               string
		opts               *core.ScanOptions
		rate, conc         int
		wantRate, wantConc int
	}{
		{"no options", nil, 150, 50, 50, 25},
		{"defaults", &core.ScanOptions{Settings: resolve()}, 150, 50, 50, 25},
		{"a cap below the level", &core.ScanOptions{Settings: resolve()}, 10, 5, 10, 5},
		{"unlimited", nil, 0, 0, 50, 25},
		{"the job's cap is not a choice", &core.ScanOptions{Settings: resolve(core.SettingsLayer{Source: core.SettingSourceJob, Values: map[string]any{"rate_limit": 100}})}, 100, 50, 50, 25},
		{"the sensor's raise", &core.ScanOptions{Settings: resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: map[string]any{"rate_limit": 400}})}, 400, 50, 400, 25},
		{"the scan's value", &core.ScanOptions{Settings: resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"threads": 40}})}, 150, 40, 50, 40},
		{"chosen, then capped by the job", &core.ScanOptions{ChosenSettings: []string{"rate_limit"}}, 120, 50, 120, 25},
	} {
		r, c := pl.Fit(tc.opts, tc.rate, tc.conc)
		if r != tc.wantRate || c != tc.wantConc {
			t.Errorf("%s: %d/%d, want %d/%d", tc.name, r, c, tc.wantRate, tc.wantConc)
		}
	}
	if Chosen(nil, "rate_limit") || Chosen(&core.ScanOptions{ChosenSettings: []string{"x"}}, "") {
		t.Error("chosen without a choice")
	}
	keys := ChosenKeys(&core.ScanOptions{ChosenSettings: []string{"threads"},
		Settings: resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"rate_limit": 100}})})
	if len(keys) != 2 || keys[0] != "rate_limit" || keys[1] != "threads" {
		t.Errorf("ChosenKeys = %v, want [rate_limit threads]", keys)
	}
	if ChosenKeys(nil) != nil || len(ChosenKeys(&core.ScanOptions{Settings: resolve()})) != 0 {
		t.Error("ChosenKeys of defaults is not empty")
	}
	if Pacing().Name != "standard" {
		t.Errorf("default level %q", Pacing().Name)
	}
}
