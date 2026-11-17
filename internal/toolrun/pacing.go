package toolrun

import (
	"log/slog"
	"slices"
	"sync/atomic"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sensor/internal/egressenv"
)

// Pacing: a scan tool works each host at the
// scan's per-host budget (Budget; Standard by default: 20 requests/s and 8
// in flight per host), mapped to the tool's own flags by its adapter. The
// schema's defaults (nuclei's and the recon tools' own 150/s) stay the most
// a scan may ask for without an administrator raising it; they are not
// what a scan runs at, and a value a person chose above the budget is
// lowered to it and recorded (PacedLimits.Fit).

// Pacing is the level a tool runs at when its caller has no scan options
// (the sensor's default budget).
func Pacing() adapt.Pacing { return adapt.DefaultPacing }

// Budget is the per-host budget of the scan: what the command executor
// resolved as the lowest of the sensor's level, the job's signed budget and
// the operator's per-host ceiling (core.ScanOptions.HostBudget). A scan
// started by anything else (a test, a direct call) runs under
// adapt.FallbackBudget: the lowest of the sensor's level, Standard and the
// operator's per-host ceiling. Every tool that sends requests to its
// targets (traffic.go) derives its flags from it and hands it to the tool
// host, whose forwarder holds each host to it where it can count (docs/
// REFERENCE.md, "Per-host budget").
func Budget(opts *core.ScanOptions) adapt.HostBudget {
	if opts == nil || !opts.HostBudget.Valid() {
		return adapt.FallbackBudget()
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
	// ChosenRate and ChosenConcurrency: the operator chose the value in the
	// tool's own config on the sensor (a scanner's ChooseLimits). With a
	// settings key a person set (Chosen) it is what makes a lowered value a
	// recorded clamp, not a default that was paced.
	ChosenRate, ChosenConcurrency bool
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
// person did not replace in opts; under a hard limit (the host budget) a
// value a person chose is lowered too. It returns, besides the values, one
// clamp for each value a person asked for that the host budget lowered:
// what was asked and what applies. A default that was paced is no clamp.
func (p PacedLimits) Fit(opts *core.ScanOptions, rate, concurrency int) (int, int, []adapt.BudgetClamp) {
	var clamps []adapt.BudgetClamp
	fit := func(key string, paced, value int, chosen bool) int {
		chosen = chosen || Chosen(opts, key)
		if paced <= 0 || (!p.Hard && chosen) || (value > 0 && paced >= value) {
			return value
		}
		if p.Hard && chosen && value > paced {
			clamps = append(clamps, adapt.BudgetClamp{Key: key, Asked: value, To: paced, By: adapt.LimitHostBudget})
		}
		return paced
	}
	rate = fit(p.RateKey, p.Rate, rate, p.ChosenRate || scanAsked(opts, true))
	concurrency = fit(p.ConcurrencyKey, p.Concurrency, concurrency, p.ChosenConcurrency || scanAsked(opts, false))
	return rate, concurrency, clamps
}

// scanAsked reports whether the scan itself names a rate (or a
// concurrency): the value then came from the scan's request, not from a
// tool's default.
func scanAsked(opts *core.ScanOptions, rate bool) bool {
	if opts == nil {
		return false
	}
	if rate {
		return opts.RateLimit > 0
	}
	return opts.Concurrency > 0
}

// LogClamps writes one line for each value the host budget lowered, for a
// run that has no tool host to state them (a tool in the sensor's own
// process). A run through the tool host carries them in its budget
// (BudgetFor) and the tool host logs them with the run.
func LogClamps(tool string, clamps []adapt.BudgetClamp) {
	for _, c := range clamps {
		slog.Warn("host budget: a setting above the budget was lowered", "tool", tool, "setting", c.Key, "asked", c.Asked, "applied", c.To, "by", c.By)
	}
}

// InProcessRate is the target-rate outcome of a scan that ran in the
// sensor's own process, without the tool host: the budget its flags were
// derived from (with what it lowered) and that nothing else enforced it.
func InProcessRate(b adapt.HostBudget, clamps []adapt.BudgetClamp) *adapt.Summary {
	s := adapt.LimitedSummary(*BudgetFor(b, clamps), adapt.PacingLimitedNoForwarder)
	return &s
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
