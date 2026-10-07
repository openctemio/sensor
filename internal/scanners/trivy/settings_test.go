package trivy

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

func TestWithSettings_ReachTheArgs(t *testing.T) {
	sc, err := NewScanner().withSettings(resolveSettings(t, map[string]any{"dev_deps": true, "os_pkgs": false, "frameworks": []any{"terraform", "dockerfile"}}))
	if err != nil {
		t.Fatal(err)
	}
	got := sc.buildArgs("/src", nil)
	if !slices.Contains(got, "--include-dev-deps") {
		t.Fatalf("args = %q", got)
	}
	if i := slices.Index(got, "--pkg-types"); i < 0 || got[i+1] != "library" {
		t.Fatalf("args = %q", got)
	}
	if i := slices.Index(got, "--misconfig-scanners"); i < 0 || got[i+1] != "terraform,dockerfile" {
		t.Fatalf("args = %q", got)
	}
	sc, _ = NewScanner().withSettings(resolveSettings(t, map[string]any{"os_pkgs": true}))
	if got := sc.buildArgs("/src", nil); got[slices.Index(got, "--pkg-types")+1] != "os,library" {
		t.Fatalf("args = %q", got)
	}
	if got := NewScanner().buildArgs("/src", nil); slices.Contains(got, "--pkg-types") || slices.Contains(got, "--include-dev-deps") {
		t.Fatalf("defaults changed: %q", got)
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
	for _, v := range []map[string]any{{"frameworks": []any{"--config"}}, {"frameworks": []any{"ansible"}}, {"frameworks": []any{}}, {"dev_deps": "true"}} {
		if _, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
}

// A capability job maps the standard param through the descriptor.
func TestCapabilityJobMapsParams(t *testing.T) {
	opts := &core.ScanOptions{Capability: "iac.misconfig@1", Params: map[string]json.RawMessage{"frameworks": json.RawMessage(`["helm"]`)}}
	_, mapped, err := toolrun.ApplyJob(context.Background(), ToolManifest, settingsSchema, opts)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := NewScanner().forScan(mapped)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sc.MisconfigScanners, []string{"helm"}) {
		t.Fatalf("frameworks %v", sc.MisconfigScanners)
	}
}
