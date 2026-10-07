package subfinder

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func TestWithSettings_ReachTheArgs(t *testing.T) {
	ts := resolve(t, map[string]any{"sources": []any{"crtsh", "hackertarget"}, "recursive": true, "max_results": 2})
	rs, err := NewAggressiveScanner().WithSettings(ts)
	if err != nil {
		t.Fatal(err)
	}
	s := rs.(*Scanner)
	got := s.buildArgs("example.com", nil)
	if !slices.Contains(got, "crtsh,hackertarget") || !slices.Contains(got, "-recursive") || slices.Contains(got, "-all") {
		t.Fatalf("args = %q", got)
	}
	flagcheck.Check(t, helpFile, got)
	if s.MaxResults != 2 {
		t.Fatalf("max_results = %d", s.MaxResults)
	}
}

func TestCapPerDomain(t *testing.T) {
	subs := []core.Subdomain{{Host: "a.x.com", Domain: "x.com"}, {Host: "b.x.com", Domain: "x.com"}, {Host: "c.x.com", Domain: "x.com"}, {Host: "a.y.com", Domain: "y.com"}}
	got := capPerDomain(subs, 2)
	if len(got) != 3 || got[2].Host != "a.y.com" {
		t.Fatalf("got %+v", got)
	}
	if len(capPerDomain(subs, 0)) != 4 {
		t.Fatal("0 keeps all")
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
	for _, v := range []map[string]any{{"sources": []any{"-o"}}, {"sources": []any{"crtsh\n-o"}}, {"sources": []any{"crtsh,github"}}, {"max_results": 0}, {"max_results": 9000}, {"sources": []any{}}} {
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
