package naabu

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Every option the manifest names a native flag for reaches naabu as that
// flag: the manifest and the argv cannot drift.
func TestManifestFlagsReachTheArgv(t *testing.T) {
	cases := []map[string]any{
		{"ports": "80,443", "exclude_ports": "25", "rate": 50, "retries": 0},
		{"top_ports": 1000},
	}
	seen := map[string]bool{}
	for _, values := range cases {
		ts, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: values})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := NewScanner().WithSettings(ts)
		if err != nil {
			t.Fatal(err)
		}
		args := rs.(*Scanner).buildArgs("a.example", &core.ReconOptions{})
		for k := range values {
			p := settingsSchema.Property(k)
			if p.Flag == "" {
				t.Fatalf("%s has no x-octm-flag", k)
			}
			if !slices.Contains(args, p.Flag) {
				t.Errorf("%s: %s missing from %v", k, p.Flag, args)
			}
			seen[k] = true
		}
	}
	for _, p := range settingsSchema.Properties {
		if !seen[p.Name] {
			t.Errorf("%s is not exercised", p.Name)
		}
	}
}
