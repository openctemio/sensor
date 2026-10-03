package nuclei

import (
	"slices"
	"strconv"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func flagValue(t *testing.T, args []string, flag string) int {
	t.Helper()
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("%s missing in %v", flag, args)
	}
	n, err := strconv.Atoi(args[i+1])
	if err != nil {
		t.Fatalf("%s %q", flag, args[i+1])
	}
	return n
}

// A scan may lower nuclei's rate limit, concurrency and bulk size, never
// raise them past the operator's ceilings; the flags are always passed.
func TestRateLimitCeiling(t *testing.T) {
	s := NewScanner()
	s.Limits = Limits{MaxRateLimit: 50, MaxConcurrency: 10, MaxBulkSize: 5}

	// Asking for more than the ceiling: the ceiling.
	args := s.buildArgs("https://example.com", &core.ScanOptions{RateLimit: 100000, Concurrency: 500, BulkSize: 1000})
	if r, c, b := flagValue(t, args, "-rate-limit"), flagValue(t, args, "-c"), flagValue(t, args, "-bs"); r != 50 || c != 10 || b != 5 {
		t.Errorf("rate %d, c %d, bs %d; want the ceilings 50, 10, 5", r, c, b)
	}
	// Nothing asked: the scanner's defaults (150/25/25), capped.
	args = s.buildArgs("https://example.com", nil)
	if r, c, b := flagValue(t, args, "-rate-limit"), flagValue(t, args, "-c"), flagValue(t, args, "-bs"); r != 50 || c != 10 || b != 5 {
		t.Errorf("rate %d, c %d, bs %d; want the ceilings 50, 10, 5", r, c, b)
	}
	// Asking for less: as asked.
	args = s.buildArgs("https://example.com", &core.ScanOptions{RateLimit: 7, Concurrency: 2, BulkSize: 1})
	if r, c, b := flagValue(t, args, "-rate-limit"), flagValue(t, args, "-c"), flagValue(t, args, "-bs"); r != 7 || c != 2 || b != 1 {
		t.Errorf("rate %d, c %d, bs %d; want 7, 2, 1", r, c, b)
	}
	// No operator ceilings: nuclei's defaults are the ceiling.
	args = NewScanner().buildArgs("https://example.com", &core.ScanOptions{RateLimit: 100000})
	if r := flagValue(t, args, "-rate-limit"); r != DefaultMaxRateLimit {
		t.Errorf("rate %d, want the default ceiling %d", r, DefaultMaxRateLimit)
	}
	// Even with every scanner field cleared, the flags are passed.
	bare := &Scanner{}
	args = bare.buildArgs("https://example.com", nil)
	if r := flagValue(t, args, "-rate-limit"); r != DefaultMaxRateLimit {
		t.Errorf("rate %d, want %d", r, DefaultMaxRateLimit)
	}
	// Free-form rate-limit flags are refused, not appended.
	if _, err := s.Scan(t.Context(), "https://example.com", &core.ScanOptions{ExtraArgs: []string{"-rate-limit", "100000"}}); err == nil {
		t.Error("-rate-limit in extra args accepted")
	}
	if _, err := s.Scan(t.Context(), "https://example.com", &core.ScanOptions{ExtraArgs: []string{"-per-host-rate-limit"}}); err == nil {
		t.Error("-per-host-rate-limit in extra args accepted")
	}
}

func TestLimitsFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	l, err := LimitsFromEnv(env(map[string]string{EnvMaxRateLimit: "40", EnvMaxConcurrency: " 8 ", EnvMaxBulkSize: ""}))
	if err != nil || l != (Limits{MaxRateLimit: 40, MaxConcurrency: 8}) {
		t.Fatalf("limits %+v, %v", l, err)
	}
	for _, bad := range []string{"0", "-5", "fast", "1.5", "2000000"} {
		if _, err := LimitsFromEnv(env(map[string]string{EnvMaxRateLimit: bad})); err == nil {
			t.Errorf("%s=%q accepted", EnvMaxRateLimit, bad)
		}
	}
}
