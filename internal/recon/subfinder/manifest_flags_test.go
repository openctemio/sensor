package subfinder

import (
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// Every option the manifest names a native flag for reaches subfinder as that
// flag: the manifest, the argv and the pinned tool cannot drift.
func TestManifestFlagsReachTheArgv(t *testing.T) {
	flagcheck.ManifestFlags(t, helpFile, settingsSchema, []map[string]any{{"sources": []any{"crtsh"}, "recursive": true, "rate_limit": 40, "timeout": 5}}, map[string]string{"sources": "crtsh", "rate_limit": "40", "timeout": "5"}, func(v map[string]any) []string {
		rs, err := NewScanner().WithSettings(resolve(t, v))
		if err != nil {
			t.Fatal(err)
		}
		return rs.(*Scanner).buildArgs("example.com", nil)
	})
}
