package opengrep

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func resolve(t *testing.T, src core.SettingSource, v map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := settingsSchema.Resolve(core.SettingsLayer{Source: src, Values: v})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestWithSettings(t *testing.T) {
	sc, err := NewScanner().withSettings(resolve(t, core.SettingSourceScan, map[string]any{
		"taint_intrafile": true, "rule_timeout": 20, "max_target_bytes": 500000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !sc.TaintIntrafile || sc.RuleTimeout != 20 || sc.MaxTargetBytes != 500000 {
		t.Fatalf("scan settings not applied: %+v", sc)
	}
	sc, err = NewScanner().withSettings(resolve(t, core.SettingSourceSensor, map[string]any{"jobs": 2, "max_memory_mb": 2048}))
	if err != nil {
		t.Fatal(err)
	}
	if sc.Jobs != 2 || sc.MaxMemory != 2048 {
		t.Fatalf("sensor settings not applied: %+v", sc)
	}
}

// The cores and memory one scan takes are the sensor's decision: a scan
// cannot set them.
func TestSettings_SensorScopeNotFromScan(t *testing.T) {
	for _, v := range []map[string]any{{"jobs": 64}, {"max_memory_mb": 65536}} {
		if _, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("a scan set %v", v)
		}
	}
}

// SECURITY: a value that could become a flag, or one out of range, never
// passes the schema.
func TestSettingsSchema_RefusesHostileValues(t *testing.T) {
	for _, v := range []map[string]any{
		{"taint_intrafile": "yes"}, {"rule_timeout": "5 --config p/default"}, {"rule_timeout": 0},
		{"rule_timeout": 601}, {"max_target_bytes": -1}, {"config": "p/default"},
	} {
		if _, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
}

func TestWithSettings_OtherSchemaRefused(t *testing.T) {
	other := core.MustParseSettingsSchema(`{"type":"object","x-octm-schema-version":1,"additionalProperties":false,"properties":{"x":{"type":"boolean","x-octm-scope":"scan"}}}`)
	ts, err := other.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"x": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewScanner().withSettings(ts); err == nil || !strings.Contains(err.Error(), "resolved against schema") {
		t.Fatalf("err = %v", err)
	}
	s := NewScanner()
	if got, err := s.forScan(&core.ScanOptions{}); err != nil || got != s {
		t.Fatal("a scan without settings keeps the scanner")
	}
}
