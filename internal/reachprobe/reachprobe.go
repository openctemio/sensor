// Package reachprobe is the sensor's reach probe: a cheap test, on the
// platform's request, of whether this sensor reaches a job's targets (one
// TCP connect per address and port until one answers, no payload, no
// ICMP). It runs sdk-go's reach.Probe through the sensor's local policy,
// the guarded dialer: only addresses the job admitted and the policy
// allows are dialed, by address, never by name. Design: api RFC-089 §4.3,
// docs/rfcs/RFC-089-reachability-aware-routing.md in openctemio/openctem.
//
// The probe is a scanner ("reach-probe"), so a probe job passes the same
// target admission as any scan before it starts. Its outcome is the job's
// reach summary (result metadata "reach", "unreached_targets"); it reports
// no findings or assets.
package reachprobe

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

const (
	// Name is the probe's scanner name.
	Name = "reach-probe"
	// Capability is what a sensor with the probe advertises.
	Capability = "reach.probe@1"
	// version of the probe's behaviour (ports, bounds).
	version = "1.0.0"
	// tier is the probe's intrusiveness: active, non-intrusive.
	tier = "T1"
)

// ErrNoPolicy refuses a probe when the sensor has no guard to dial through.
var ErrNoPolicy = errors.New("reach-probe: no local policy to dial through; the probe never dials unguarded")

// Scanner is the reach probe as a scanner.
type Scanner struct {
	// guard is the local policy in force when a probe starts (a reload
	// applies to the next probe).
	guard func() reach.Guard
	// dial opens connections (nil: a plain dialer); tests replace it.
	dial reach.DialFunc
}

var (
	_ core.Scanner            = (*Scanner)(nil)
	_ core.MultiTargetScanner = (*Scanner)(nil)
	_ core.CapabilityScanner  = (*Scanner)(nil)
)

// New returns the probe; guard returns the local policy in force (nil
// refuses every probe).
func New(guard func() reach.Guard) *Scanner {
	return &Scanner{guard: guard}
}

// WithDial makes the probe open connections with dial (nil: a plain
// dialer); every address still comes from the guard.
func (s *Scanner) WithDial(dial reach.DialFunc) *Scanner {
	s.dial = dial
	return s
}

// Name is the scanner name.
func (s *Scanner) Name() string { return Name }

// Version is the probe's version.
func (s *Scanner) Version() string { return version }

// Capabilities is the probe's capability.
func (s *Scanner) Capabilities() []string { return []string{Capability} }

// IsInstalled: the probe is built in.
func (s *Scanner) IsInstalled(context.Context) (bool, string, error) { return true, version, nil }

// TakesCapabilityJobs: a probe job may name the probe's capability and a
// tier ceiling (checked by checkJob).
func (s *Scanner) TakesCapabilityJobs() bool { return true }

// Scan probes one target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// ScanTargets probes the job's targets (already admitted by the command
// executor; each is checked again by the guard). Every outcome goes to the
// job's reach recorder.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if err := checkJob(opts); err != nil {
		return nil, err
	}
	var guard reach.Guard
	if s.guard != nil {
		guard = s.guard()
	}
	if guard == nil {
		return nil, ErrNoPolicy
	}
	start := time.Now()
	res, err := Probe(ctx, guard, s.dial, targets, rateOf(opts))
	if err != nil {
		return nil, fmt.Errorf("reach-probe: %w", err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if opts != nil && opts.Verbose {
		fmt.Printf("[reach-probe] %d address(es) probed, %d reached, %d not reached, %d not probed (bound), %d refused by the policy\n",
			res.Probed, res.Reached, res.Unreached, res.NotProbed, res.RefusedTotal)
	}
	finished := time.Now()
	return &core.ScanResult{
		ScannerName:    Name,
		ScannerVersion: version,
		StartedAt:      start.Unix(),
		FinishedAt:     finished.Unix(),
		DurationMs:     finished.Sub(start).Milliseconds(),
	}, nil
}

// Probe runs reach.Probe with the sensor's bounds through guard: the
// default ports, at most rate connects per second (never above
// reach.MaxProbeRate), every outcome also recorded into the job's
// recorder (ctx's). dial nil is a plain dialer.
func Probe(ctx context.Context, guard reach.Guard, dial reach.DialFunc, targets []string, rate float64) (reach.ProbeResult, error) {
	return reach.Probe(ctx, guard, targets, reach.ProbeOptions{
		Dial:     dial,
		Rate:     rate,
		Recorder: reach.FromContext(ctx),
	})
}

// checkJob refuses a job the probe cannot keep to: another capability, a
// tier ceiling below the probe's, a web scope or scope limits (the probe
// connects to ports the limits may not allow and takes no paths).
func checkJob(opts *core.ScanOptions) error {
	if opts == nil {
		return nil
	}
	if opts.Capability != "" && opts.Capability != Capability {
		return fmt.Errorf("reach-probe does not implement capability %q", opts.Capability)
	}
	if opts.MaxTier == "T0" {
		return fmt.Errorf("reach-probe is tier %s (it opens connections); the job allows T0 only", tier)
	}
	if opts.WebScope != nil {
		return errors.New("reach-probe does not keep to a web scope; the job has one")
	}
	if len(opts.Limits) > 0 {
		return errors.New("reach-probe cannot keep to the job's port or path limits")
	}
	return nil
}

// rateOf is the job's connects per second: its rate_limit (already capped
// by the local policy's rate.max_rps) when lower than the probe's bound.
func rateOf(opts *core.ScanOptions) float64 {
	if opts != nil && opts.RateLimit > 0 && opts.RateLimit < reach.MaxProbeRate {
		return float64(opts.RateLimit)
	}
	return reach.MaxProbeRate
}
