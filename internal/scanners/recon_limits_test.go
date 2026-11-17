package scanners

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sensor/internal/toolrun"
)

// fit2 is PacedLimits.Fit without the clamps.
func fit2(pl toolrun.PacedLimits, rate, conc int) (int, int) {
	r, c, _ := pl.Fit(nil, rate, conc)
	return r, c
}

// The host budget bounds httpx's and katana's rate and concurrency, also
// the operator's own values in the sensor's scanner config; under a budget
// above them (a sensor whose operator set the Fast level) the operator's
// values stand.
func TestReconLimitsUnderTheHostBudget(t *testing.T) {
	std := adapt.DefaultBudget()
	fast := adapt.ResolveBudget(adapt.PacingFast, nil, adapt.BudgetCeiling{})
	hx := HTTPXWithConfig(HTTPXOptions{RateLimit: 120, Threads: 40})
	kt := KatanaWithConfig(KatanaOptions{RateLimit: 90, Concurrency: 30})
	for _, c := range []struct {
		name             string
		rate, conc       int
		wantRate, wantCn int
		fit              func(rate, conc int) (int, int)
	}{
		{"httpx config, one host (two requests a target)", 120, 40, 10, 8, func(r, n int) (int, int) { return fit2(hx.PacedLimits(std, 1, true), r, n) }},
		{"httpx config, a hundred hosts", 120, 40, 50, 25, func(r, n int) (int, int) { return fit2(hx.PacedLimits(std, 100, true), r, n) }},
		{"httpx config, one host, fast", 120, 40, 50, 25, func(r, n int) (int, int) { return fit2(hx.PacedLimits(fast, 1, true), r, n) }},
		{"httpx config, a hundred hosts, fast", 120, 40, 120, 40, func(r, n int) (int, int) { return fit2(hx.PacedLimits(fast, 100, true), r, n) }},
		{"httpx default, one host", 150, 50, 10, 8, func(r, n int) (int, int) { return fit2(HTTPX().PacedLimits(std, 1, true), r, n) }},
		{"katana config, one host", 90, 30, 20, 8, func(r, n int) (int, int) { return fit2(kt.PacedLimits(std, 1, true), r, n) }},
		{"katana config, one host, fast", 90, 30, 90, 25, func(r, n int) (int, int) { return fit2(kt.PacedLimits(fast, 1, true), r, n) }},
		{"katana default, three hosts", 150, 10, 60, 10, func(r, n int) (int, int) { return fit2(Katana().PacedLimits(std, 3, true), r, n) }},
		{"katana default, three hosts, unconfined", 150, 10, 20, 8, func(r, n int) (int, int) { return fit2(Katana().PacedLimits(std, 3, false), r, n) }},
	} {
		if r, n := c.fit(c.rate, c.conc); r != c.wantRate || n != c.wantCn {
			t.Errorf("%s: %d/%d, want %d/%d", c.name, r, n, c.wantRate, c.wantCn)
		}
	}
}
