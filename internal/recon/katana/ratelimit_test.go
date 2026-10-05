package katana

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// The scan's rate limit (the command's rate_limit, capped by the sensor
// policy) becomes the tool's own rate flag.
func TestBuildArgs_ScanRateLimit(t *testing.T) {
	got := NewScanner().buildArgs("https://example.com", &core.ReconOptions{RateLimit: 7})
	i := slices.Index(got, "-rl")
	if i < 0 || i+1 >= len(got) || got[i+1] != "7" {
		t.Fatalf("want -rl 7 in %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}
