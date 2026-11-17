package scanners

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// The host budget bounds httpx's and katana's rate and concurrency, also
// the operator's own values in the sensor's scanner config; under a budget
// above them the operator's values stand.
func TestReconLimitsUnderTheHostBudget(t *testing.T) {
	std := adapt.DefaultBudget()
	fast := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "fast"}, adapt.BudgetCeiling{})
	hx := HTTPXWithConfig(HTTPXOptions{RateLimit: 120, Threads: 40})
	kt := KatanaWithConfig(KatanaOptions{RateLimit: 90, Concurrency: 30})
	for _, c := range []struct {
		name             string
		rate, conc       int
		wantRate, wantCn int
		fit              func(rate, conc int) (int, int)
	}{
		{"httpx config, one host", 120, 40, 20, 8, func(r, n int) (int, int) { return hx.PacedLimits(std, 1, 1, true).Fit(nil, r, n) }},
		{"httpx config, a hundred hosts", 120, 40, 50, 25, func(r, n int) (int, int) { return hx.PacedLimits(std, 100, 1, true).Fit(nil, r, n) }},
		{"httpx config, one host, fast", 120, 40, 100, 25, func(r, n int) (int, int) { return hx.PacedLimits(fast, 1, 1, true).Fit(nil, r, n) }},
		{"httpx config, a hundred hosts, fast", 120, 40, 120, 40, func(r, n int) (int, int) { return hx.PacedLimits(fast, 100, 1, true).Fit(nil, r, n) }},
		{"httpx default, one host", 150, 50, 20, 8, func(r, n int) (int, int) { return HTTPX().PacedLimits(std, 1, 1, true).Fit(nil, r, n) }},
		{"katana config, one host", 90, 30, 20, 8, func(r, n int) (int, int) { return kt.PacedLimits(std, 1, 1, true).Fit(nil, r, n) }},
		{"katana config, one host, fast", 90, 30, 90, 25, func(r, n int) (int, int) { return kt.PacedLimits(fast, 1, 1, true).Fit(nil, r, n) }},
		{"katana default, three hosts", 150, 10, 60, 10, func(r, n int) (int, int) { return Katana().PacedLimits(std, 3, 1, true).Fit(nil, r, n) }},
		{"katana default, three hosts, unconfined", 150, 10, 20, 8, func(r, n int) (int, int) { return Katana().PacedLimits(std, 3, 1, false).Fit(nil, r, n) }},
	} {
		if r, n := c.fit(c.rate, c.conc); r != c.wantRate || n != c.wantCn {
			t.Errorf("%s: %d/%d, want %d/%d", c.name, r, n, c.wantRate, c.wantCn)
		}
	}
}
