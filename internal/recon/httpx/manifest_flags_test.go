package httpx

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// Every option the manifest names a native flag for reaches httpx as that
// flag: the manifest, the argv and the pinned tool cannot drift.
func TestManifestFlagsReachTheArgv(t *testing.T) {
	flagcheck.ManifestFlags(t, helpFile, settingsSchema, []map[string]any{{"ports": "80,443", "follow_redirects": true, "tech_detect": true, "tls_grab": true, "rate_limit": 40, "threads": 7, "timeout": 5, "retries": 1}}, map[string]string{"ports": "80,443", "rate_limit": "40", "threads": "7", "timeout": "5", "retries": "1"}, func(v map[string]any) []string {
		rs, err := NewScanner().WithSettings(resolve(t, v))
		if err != nil {
			t.Fatal(err)
		}
		return rs.(*Scanner).buildArgs("example.com", nil)
	})
}

// Only the sensor's settings raise the rate above the default; the raise is
// what Limits reports to the recon runner (which only lowers it further). A
// scan asking for more is refused, not applied.
func TestRateRaiseIsTheSensorsAlone(t *testing.T) {
	ts, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: map[string]any{"rate_limit": 400, "threads": 80}})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewScanner().WithSettings(ts)
	if err != nil {
		t.Fatal(err)
	}
	if rate, conc := rs.(*Scanner).Limits(); rate != 400 || conc != 80 {
		t.Fatalf("Limits = %d, %d", rate, conc)
	}
	if _, err := settingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"rate_limit": 400}}); err == nil {
		t.Fatal("a scan raised the rate above the default")
	}
}
