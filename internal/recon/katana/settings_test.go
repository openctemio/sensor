package katana

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func TestWithSettings_ReachTheArgs(t *testing.T) {
	rs, err := NewScanner().WithSettings(resolve(t, map[string]any{"depth": 5, "js_parse": false, "max_urls": 10}))
	if err != nil {
		t.Fatal(err)
	}
	s := rs.(*Scanner)
	got := s.buildArgs("https://example.com", nil)
	if i := slices.Index(got, "-d"); i < 0 || got[i+1] != "5" || slices.Contains(got, "-js-crawl") {
		t.Fatalf("args = %q", got)
	}
	flagcheck.Check(t, helpFile, got)
	if s.MaxURLs != 10 {
		t.Fatalf("max_urls = %d", s.MaxURLs)
	}
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
	for _, v := range []map[string]any{{"depth": 0}, {"depth": 11}, {"max_urls": 5001}, {"js_parse": "-x"}} {
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
