package dnsx

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func TestWithSettings_ReachTheArgs(t *testing.T) {
	rs, err := NewScanner().WithSettings(resolve(t, map[string]any{"record_types": []any{"mx", "txt"}, "wildcard_filter": true}))
	if err != nil {
		t.Fatal(err)
	}
	got := rs.(*Scanner).buildArgs("example.com", nil)
	if !slices.Contains(got, "-mx") || !slices.Contains(got, "-txt") || slices.Contains(got, "-a") || !slices.Contains(got, "-auto-wildcard") {
		t.Fatalf("args = %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}

// Settings resolved against another schema (another tool, another build)
// are refused, never guessed at.
func TestWithSettings_OtherSchemaRefused(t *testing.T) {
	other := core.MustParseSettingsSchema(`{"type":"object","x-octm-schema-version":1,"additionalProperties":false,"properties":{"x":{"type":"boolean","x-octm-scope":"scan"}}}`)
	ts, err := other.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"x": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewScanner().WithSettings(ts); err == nil || !strings.Contains(err.Error(), "resolved against schema") {
		t.Fatalf("err = %v", err)
	}
	if got, err := NewScanner().WithSettings(nil); err != nil || got == nil {
		t.Fatal("nil settings keep the scanner")
	}
}

// SECURITY: a value that could become a flag or a second argument never
// passes the schema.
func TestSettingsSchema_RefusesHostileValues(t *testing.T) {
	for _, v := range []map[string]any{{"record_types": []any{"axfr"}}, {"record_types": []any{"-a"}}, {"record_types": []any{}}, {"wildcard_filter": "yes"}} {
		if _, err := NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
}

func resolve(t *testing.T, v map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}
