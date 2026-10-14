package dnsx

import (
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// Every option the manifest names a native flag for reaches dnsx as that
// flag: the manifest, the argv and the pinned tool cannot drift.
func TestManifestFlagsReachTheArgv(t *testing.T) {
	flagcheck.ManifestFlags(t, helpFile, settingsSchema, []map[string]any{{"wildcard_filter": true, "rate_limit": 40, "threads": 7, "timeout": 5, "retries": 0}}, map[string]string{"rate_limit": "40", "threads": "7", "timeout": "5s", "retries": "1"}, func(v map[string]any) []string {
		rs, err := NewScanner().WithSettings(resolve(t, v))
		if err != nil {
			t.Fatal(err)
		}
		return rs.(*Scanner).buildArgs("example.com", nil)
	})
}
