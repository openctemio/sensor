package toolrun

import (
	"slices"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
)

// Pacing (research 518, decision D1): unless a person chose a value, a scan
// tool works each host at the pacing level (adapt.DefaultPacing, Standard:
// 20 requests/s and 8 in flight per host), mapped to the tool's own flags by
// its adapter. The schema's defaults (nuclei's and the recon tools' own
// 150/s) stay the most a scan may ask for without an administrator raising
// it; they are no longer what a scan that asks nothing runs at.

// Pacing is the level the tools run at.
func Pacing() adapt.Pacing { return adapt.DefaultPacing }

// Chosen reports whether a person set the settings key: in the tenant's,
// the sensor's or the scan's layer (opts.ChosenSettings, kept when the job's
// or the local policy's caps lowered the value afterwards), or as a mapped
// capability parameter of the scan. A tool's default, the job's decision
// (scan windows, program rules) and the local policy only cap a value: the
// pacing level still applies under them.
func Chosen(opts *core.ScanOptions, key string) bool {
	if opts == nil || key == "" {
		return false
	}
	if slices.Contains(opts.ChosenSettings, key) {
		return true
	}
	switch opts.Settings.Source(key) {
	case core.SettingSourceTenant, core.SettingSourceSensor, core.SettingSourceProfile, core.SettingSourceScan:
		return true
	}
	return false
}

// PacedLimits are a tool's rate and concurrency at a pacing level, and the
// settings keys a person sets them with (empty: the tool has none).
type PacedLimits struct {
	RateKey        string
	Rate           int
	ConcurrencyKey string
	Concurrency    int
}

// Fit lowers rate and concurrency (0: unlimited) to the paced values a
// person did not replace in opts.
func (p PacedLimits) Fit(opts *core.ScanOptions, rate, concurrency int) (int, int) {
	if p.Rate > 0 && !Chosen(opts, p.RateKey) && (rate <= 0 || p.Rate < rate) {
		rate = p.Rate
	}
	if p.Concurrency > 0 && !Chosen(opts, p.ConcurrencyKey) && (concurrency <= 0 || p.Concurrency < concurrency) {
		concurrency = p.Concurrency
	}
	return rate, concurrency
}

// ChosenKeys are every settings key a person set in opts (Chosen), for a
// tool child that gets the scan's options without its settings.
func ChosenKeys(opts *core.ScanOptions) []string {
	if opts == nil {
		return nil
	}
	keys := slices.Clone(opts.ChosenSettings)
	for _, k := range opts.Settings.Keys() {
		if Chosen(opts, k) && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}
