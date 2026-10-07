package httpx

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func TestWithSettings_ReachTheArgs(t *testing.T) {
	rs, err := NewScanner().WithSettings(resolve(t, map[string]any{"ports": "80,8000-8100", "follow_redirects": false, "tech_detect": false, "tls_grab": false}))
	if err != nil {
		t.Fatal(err)
	}
	got := rs.(*Scanner).buildArgs("example.com", nil)
	if i := slices.Index(got, "-ports"); i < 0 || got[i+1] != "80,8000-8100" {
		t.Fatalf("args = %q", got)
	}
	for _, f := range []string{"-tech-detect", "-tls-grab", "-follow-host-redirects", "-follow-redirects"} {
		if slices.Contains(got, f) {
			t.Fatalf("%s still set: %q", f, got)
		}
	}
	flagcheck.Check(t, helpFile, got)
	rs, _ = NewScanner().WithSettings(resolve(t, map[string]any{"follow_redirects": true}))
	if got := rs.(*Scanner).buildArgs("example.com", nil); !slices.Contains(got, "-follow-host-redirects") || slices.Contains(got, "-follow-redirects") {
		t.Fatalf("same-host redirects only: %q", got)
	}
}

func TestCheckPortList(t *testing.T) {
	for _, bad := range []string{"", "0", "70000", "90-80", "http:80", "80;id", "8 0"} {
		if checkPortList(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if checkPortList("1,65535,10-20") != nil {
		t.Fatal("refused a valid list")
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
	for _, v := range []map[string]any{{"ports": "-o /tmp/x"}, {"ports": "http:80"}, {"ports": "80\n443"}, {"tech_detect": 1}} {
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
