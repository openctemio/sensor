package scanners

import (
	"testing"

	"github.com/openctemio/sensor/internal/toolrun"
)

// The operator's httpx and katana limits in the sensor's scanner config
// replace the pacing level's values (a person chose them); without them the
// tools run at the level.
func TestReconConfigLimitsAreChosen(t *testing.T) {
	lvl := toolrun.Pacing()
	for _, c := range []struct {
		name             string
		limits           toolrun.PacedLimits
		rate, conc       int
		wantRate, wantCn int
	}{
		{"httpx config", HTTPXWithConfig(HTTPXOptions{RateLimit: 120, Threads: 40}).PacedLimits(lvl), 120, 40, 120, 40},
		{"httpx rate only", HTTPXWithConfig(HTTPXOptions{RateLimit: 120}).PacedLimits(lvl), 120, 50, 120, lvl.SweepInflight},
		{"httpx default", HTTPX().PacedLimits(lvl), 150, 50, lvl.SweepRPS, lvl.SweepInflight},
		{"katana config", KatanaWithConfig(KatanaOptions{RateLimit: 90, Concurrency: 30}).PacedLimits(lvl), 90, 30, 90, 30},
		{"katana default", Katana().PacedLimits(lvl), 150, 10, lvl.TargetRPS, lvl.TargetInflight},
	} {
		r, n := c.limits.Fit(nil, c.rate, c.conc)
		if r != c.wantRate || n != c.wantCn {
			t.Errorf("%s: %d/%d, want %d/%d", c.name, r, n, c.wantRate, c.wantCn)
		}
	}
}
