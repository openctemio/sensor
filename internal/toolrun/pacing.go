package toolrun

import (
	"slices"
	"sync/atomic"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sensor/internal/egressenv"
)

// Pacing (research 518, decision D1): unless a person chose a value, a scan
// tool works each host at the pacing level (adapt.DefaultPacing, Standard:
// 20 requests/s and 8 in flight per host), mapped to the tool's own flags by
// its adapter. The schema's defaults (nuclei's and the recon tools' own
// 150/s) stay the most a scan may ask for without an administrator raising
// it; they are no longer what a scan that asks nothing runs at.

// Pacing is the level a tool runs at when its caller has no scan options
// (the sensor's default budget).
func Pacing() adapt.Pacing { return adapt.DefaultPacing }

// Budget is the per-host budget of the scan (research 518, P0-1): what the
// command executor resolved from the sensor's level, the job's signed
// budget and the operator's ceiling (core.ScanOptions.HostBudget). A scan
// started by anything else (a test, a direct call) runs under the default
// budget, Standard. Every HTTP tool derives its flags from it and hands it
// to the tool host, whose forwarder holds each host to it.
func Budget(opts *core.ScanOptions) adapt.HostBudget {
	if opts == nil || !opts.HostBudget.Valid() {
		return adapt.DefaultBudget()
	}
	return opts.HostBudget
}

// PerHostEnforced reports whether something outside the tool holds each
// host to the budget: the task forwarder of a tool that runs out of
// process in a sandbox that confines its network. In the tool child that
// is the forwarder's proxy in its environment; in the sensor it is the
// runtime's own status. Without it a tool's flags are the only bound, and
// a rate flag that is global to the process gets one host's budget
// (adapt.HostBudget.ToolPace).
func PerHostEnforced() bool {
	if v := enforcedForTest.Load(); v != nil {
		return *v
	}
	if InChild() {
		return egressenv.Confined()
	}
	return OutOfProcess() && executor.Current().Status().NetworkEnforced
}

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

// enforcedForTest fixes PerHostEnforced in tests (nil: the real answer).
var enforcedForTest atomic.Pointer[bool]

// SetPerHostEnforced fixes what PerHostEnforced answers, for a test that
// asserts a tool's flags (the real answer depends on the host's sandbox);
// nil restores it.
func SetPerHostEnforced(v *bool) { enforcedForTest.Store(v) }

// PacedLimits are a tool's rate and concurrency at a pacing level, and the
// settings keys a person sets them with (empty: the tool has none).
type PacedLimits struct {
	RateKey        string
	Rate           int
	ConcurrencyKey string
	Concurrency    int
	// Hard: the values come from the host budget, which no settings layer
	// and no scanner config passes; a value a person chose is lowered to
	// them too. Not hard (a port scan's packets per second): a level's
	// default, which a chosen value replaces.
	Hard bool
}

// Without drops the paced rate and/or concurrency the operator chose
// in the tool's own config (the tool's value then stands, lowered only by
// the scan's and the job's caps).
func (p PacedLimits) Without(rate, concurrency bool) PacedLimits {
	if p.Hard {
		return p
	}
	if rate {
		p.Rate = 0
	}
	if concurrency {
		p.Concurrency = 0
	}
	return p
}

// Fit lowers rate and concurrency (0: unlimited) to the paced values a
// person did not replace in opts.
func (p PacedLimits) Fit(opts *core.ScanOptions, rate, concurrency int) (int, int) {
	if p.Rate > 0 && (p.Hard || !Chosen(opts, p.RateKey)) && (rate <= 0 || p.Rate < rate) {
		rate = p.Rate
	}
	if p.Concurrency > 0 && (p.Hard || !Chosen(opts, p.ConcurrencyKey)) && (concurrency <= 0 || p.Concurrency < concurrency) {
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
