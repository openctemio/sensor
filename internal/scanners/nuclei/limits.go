package nuclei

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Environment variables with the operator's rate-limit ceilings for nuclei.
// Unset, the ceiling is nuclei's default value (150 requests per second, 25
// templates and 25 hosts in parallel), so a scan never runs harder than a
// plain nuclei run unless the operator raises it.
const (
	EnvMaxRateLimit   = "SENSOR_NUCLEI_MAX_RATE_LIMIT"
	EnvMaxConcurrency = "SENSOR_NUCLEI_MAX_CONCURRENCY"
	EnvMaxBulkSize    = "SENSOR_NUCLEI_MAX_BULK_SIZE"
)

// Default ceilings, when the operator sets none.
const (
	DefaultMaxRateLimit   = DefaultRateLimit
	DefaultMaxConcurrency = DefaultConcurrency
	DefaultMaxBulkSize    = DefaultBulkSize
)

// Limits are the operator's ceilings for nuclei on this sensor. A zero field
// is its Default* value.
type Limits struct {
	MaxRateLimit   int // requests per second (-rate-limit)
	MaxConcurrency int // templates in parallel (-c)
	MaxBulkSize    int // hosts in parallel per template (-bs)
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// rateCeiling, concurrencyCeiling and bulkCeiling are the ceilings in force.
func (l Limits) rateCeiling() int        { return orDefault(l.MaxRateLimit, DefaultMaxRateLimit) }
func (l Limits) concurrencyCeiling() int { return orDefault(l.MaxConcurrency, DefaultMaxConcurrency) }
func (l Limits) bulkCeiling() int        { return orDefault(l.MaxBulkSize, DefaultMaxBulkSize) }

// LimitsFromEnv reads the ceilings from SENSOR_NUCLEI_MAX_RATE_LIMIT,
// SENSOR_NUCLEI_MAX_CONCURRENCY and SENSOR_NUCLEI_MAX_BULK_SIZE. A value
// that is not a whole number from 1 to core.MaxScanLimit is an error: the
// sensor must not start with a ceiling other than the one its operator
// meant.
func LimitsFromEnv(lookup func(string) (string, bool)) (Limits, error) {
	var l Limits
	for _, f := range []struct {
		env string
		dst *int
	}{
		{EnvMaxRateLimit, &l.MaxRateLimit},
		{EnvMaxConcurrency, &l.MaxConcurrency},
		{EnvMaxBulkSize, &l.MaxBulkSize},
	} {
		v, ok := lookup(f.env)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > core.MaxScanLimit {
			return Limits{}, fmt.Errorf("%s=%q: want a whole number from 1 to %d", f.env, v, core.MaxScanLimit)
		}
		*f.dst = n
	}
	return l, nil
}

// EffectiveLimits are the rate limit, concurrency and bulk size a scan with
// opts runs with: the scan's request (opts.RateLimit, Concurrency,
// BulkSize) or the scanner's own value, capped at the operator's ceiling.
func (s *Scanner) EffectiveLimits(opts *core.ScanOptions) (rate, concurrency, bulk int) {
	var req core.ScanOptions
	if opts != nil {
		req = *opts
	}
	rate = core.CapScanLimit(req.RateLimit, s.RateLimit, s.Limits.rateCeiling())
	concurrency = core.CapScanLimit(req.Concurrency, s.Concurrency, s.Limits.concurrencyCeiling())
	bulk = core.CapScanLimit(req.BulkSize, s.BulkSize, s.Limits.bulkCeiling())
	return rate, concurrency, bulk
}
