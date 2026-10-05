package nuclei

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func scanSettings(t *testing.T, values map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: values})
	if err != nil {
		t.Fatalf("resolve %v: %v", values, err)
	}
	return ts
}

func argsWith(t *testing.T, s *Scanner, values map[string]any) []string {
	t.Helper()
	sc, err := s.forScan(&core.ScanOptions{Settings: scanSettings(t, values)})
	if err != nil {
		t.Fatalf("settings %v: %v", values, err)
	}
	return sc.buildArgs("https://example.com", nil)
}

func settingFlag(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

// A pipeline step's tags and severities select the templates. Before, the
// step's config never reached nuclei and it ran its defaults.
func TestSettings_TagsAndSeverity(t *testing.T) {
	got := argsWith(t, NewScanner(), map[string]any{
		"tags":     []any{"cve", "exposure"},
		"severity": []any{"high", "critical"},
	})
	if v := settingFlag(got, "-tags"); v != "cve,exposure" {
		t.Errorf("-tags = %q in %q", v, got)
	}
	if v := settingFlag(got, "-severity"); v != "high,critical" {
		t.Errorf("-severity = %q in %q", v, got)
	}
}

// SECURITY: a scan's excluded tags are added to the sensor's, never
// replacing them, so a scan cannot re-enable what the operator excluded.
func TestSettings_ExcludeTagsAreAdded(t *testing.T) {
	s := NewDAST() // excludes dos, fuzz
	got := argsWith(t, s, map[string]any{"exclude_tags": []any{"wordpress", "dos"}})
	if v := settingFlag(got, "-etags"); v != strings.Join(T1ExcludedTags, ",")+",wordpress" {
		t.Errorf("-etags = %q", v)
	}
	if !slices.Equal(s.ExcludeTags, []string{"dos", "fuzz"}) {
		t.Errorf("scanner's own exclusions changed: %v", s.ExcludeTags)
	}
}

// The scanner is not modified by a scan's settings.
func TestSettings_DoNotModifyTheScanner(t *testing.T) {
	s := NewScanner()
	before := s.buildArgs("https://example.com", nil)
	_ = argsWith(t, s, map[string]any{"tags": []any{"cve"}, "severity": []any{"info"}})
	if after := s.buildArgs("https://example.com", nil); !slices.Equal(before, after) {
		t.Errorf("args changed from %q to %q", before, after)
	}
}

// SECURITY: settings cannot inject flags, enable code/file/headless
// templates or protocols, set template paths, output files, proxies,
// interaction servers or rate limits.
func TestSettings_RefuseInjection(t *testing.T) {
	schema := NewScanner().SettingsSchema()
	for _, v := range []map[string]any{
		{"tags": []any{"-code"}},
		{"tags": []any{"cve -code"}},
		{"tags": []any{"cve,code"}},
		{"tags": []any{"cve\n-headless"}},
		{"tags": "cve"},
		{"severity": []any{"high", "-o"}},
		{"severity": []any{}},
		{"templates": []any{"/etc/passwd"}},
		{"template_dir": "/"},
		{"code": true},
		{"headless": true},
		{"file": true},
		{"proxy": "http://attacker:8080"},
		{"interactsh_server": "https://oast.attacker"},
		{"output": "/etc/cron.d/x"},
		{"rate_limit": 100000},
		{"headers": []any{"X: y"}},
	} {
		if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("schema accepted %v", v)
		}
	}
	for _, tag := range []string{"dos", "fuzz", "fuzzing", "intrusive"} {
		if _, err := NewScanner().forScan(&core.ScanOptions{Settings: scanSettings(t, map[string]any{"tags": []any{"cve", tag}})}); err == nil {
			t.Errorf("intrusive tag %q accepted", tag)
		}
	}
}

func TestSettings_RefuseAnotherSchema(t *testing.T) {
	other := core.MustParseSettingsSchema(`{"$schema":"https://json-schema.org/draft/2020-12/schema","x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{"tags":{"type":"array","items":{"type":"string"},"x-octm-scope":"scan"}}}`)
	ts, err := other.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"tags": []any{"-code"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewScanner().forScan(&core.ScanOptions{Settings: ts}); err == nil {
		t.Fatal("settings of another schema accepted")
	}
}
