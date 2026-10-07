package codeql

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

func TestWithSettings_Language(t *testing.T) {
	sc, err := NewScanner().withSettings(resolveSettings(t, map[string]any{"languages": []any{"python"}}))
	if err != nil {
		t.Fatal(err)
	}
	if sc.Language != LanguagePython || !slices.ContainsFunc(sc.buildAnalyzeArgs("/db", "/out"), func(a string) bool { return strings.HasPrefix(a, "codeql/python-queries:") }) {
		t.Fatalf("language %q args %q", sc.Language, sc.buildAnalyzeArgs("/db", "/out"))
	}
}

func resolveSettings(t *testing.T, v map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// Settings resolved against another schema are refused, never guessed at;
// a scan without settings keeps the scanner.
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

// SECURITY: a value that could become a flag never passes the schema.
func TestSettingsSchema_RefusesHostileValues(t *testing.T) {
	for _, v := range []map[string]any{{"languages": []any{"python", "go"}}, {"languages": []any{"--threads=0"}}, {"languages": []any{"cobol"}}, {"languages": []any{}}} {
		if _, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
}

// A capability job maps the standard param through the descriptor.
func TestCapabilityJobMapsParams(t *testing.T) {
	opts := &core.ScanOptions{Capability: "sast.code@1", Params: map[string]json.RawMessage{"languages": json.RawMessage(`["go"]`)}}
	_, mapped, err := toolrun.ApplyJob(context.Background(), ToolManifest, settingsSchema, opts)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner().forScan(mapped)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Language != LanguageGo {
		t.Fatalf("language %q", sc.Language)
	}
}
