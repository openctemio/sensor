package recon

// Politeness and host-bound traffic for the recon tools (api
// docs/rfcs/RFC-036-easm.md §6.13; research/22 P0-2 in openctemio/openctem).
//
//   - Rate: a scan's rate_limit / concurrency (core.ScanOptions, already
//     capped by the local policy's rate.max_rps) reach the tool, and only
//     lower the tool's own limits. Before, the wrapper dropped them, so
//     recon ran at the tools' defaults whatever the scan or the sensor
//     owner asked.
//   - Backoff: a target that answers 429 Too Many Requests or 503 halves the
//     rate of the job's later targets (down to 1 request/s) and waits before
//     the next one; the throttled targets are listed in the report
//     ("throttled_targets"). No rotation or evasion (RFC-034).
//   - Host-bound: extra args can never widen where a tool goes (follow
//     redirects to other hosts, widen or drop katana's scope).

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// limiter is a recon tool that reports its own limits.
type limiter interface {
	Limits() (rate, concurrency int)
}

// toolLimits returns a recon tool's own request rate and concurrency (0:
// the tool sets none, so it is unlimited).
func toolLimits(rs core.ReconScanner) (rate, threads int) {
	if l, ok := rs.(limiter); ok {
		return l.Limits()
	}
	return 0, 0
}

// lower returns requested when it is set and below own (or own is
// unlimited), else own.
func lower(own, requested int) int {
	if requested > 0 && (own <= 0 || requested < own) {
		return requested
	}
	return own
}

// hostBoundFlags are tool flags that would send a recon tool to hosts its
// target does not name: httpx -fr/-follow-redirects (any host; -fhr is
// same-host), katana's scope (-fs/-field-scope, -cs/-crawl-scope,
// -ns/-no-scope) and -dr/-disable-redirects (-dr=false would re-enable
// off-host redirects). They never arrive in extra args, for any tool
// (katana's -fr is a regex filter, httpx's -fs a string filter: losing
// those through extra args is the price of one list).
var hostBoundFlags = []string{
	"fr", "follow-redirects", "fs", "field-scope", "cs", "crawl-scope",
	"ns", "no-scope", "dr", "disable-redirects",
}

// checkHostBoundArgs refuses extra args that would widen where a tool goes.
func checkHostBoundArgs(args []string) error {
	for _, a := range args {
		t := strings.TrimSpace(a)
		if !strings.HasPrefix(t, "-") {
			continue
		}
		name := strings.ToLower(strings.TrimLeft(t, "-"))
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if slices.Contains(hostBoundFlags, name) {
			return fmt.Errorf("extra arg %q is not allowed: recon tools stay on the target's host", a)
		}
	}
	return nil
}

// throttleTools answer HTTP: their results carry status codes.
var throttleTools = []string{"httpx", "katana"}

// throttled reports whether a run's results show the target throttling or
// refusing the sensor (429 Too Many Requests, 503 Service Unavailable).
func throttled(r *core.ReconResult) bool {
	if r == nil {
		return false
	}
	for _, h := range r.LiveHosts {
		if h.StatusCode == 429 || h.StatusCode == 503 {
			return true
		}
	}
	for _, u := range r.URLs {
		if u.StatusCode == 429 || u.StatusCode == 503 {
			return true
		}
	}
	return false
}

// Backoff after a throttled target.
const (
	// backoffBaseRate is the rate halved when neither the scan nor the
	// tool sets one.
	backoffBaseRate = 150
	initialBackoff  = 2 * time.Second
	maxBackoff      = 30 * time.Second
)

// backoff is a job's throttling state.
type backoff struct {
	rate  int           // the rate later targets run at (0: unchanged)
	wait  time.Duration // the wait before the next target
	hosts []string      // the throttled targets
}

// hit records a throttled target: half the rate (at least 1), and twice
// the wait (at most maxBackoff).
func (b *backoff) hit(target string, rate int) {
	if rate <= 0 {
		rate = backoffBaseRate
	}
	if b.rate > 0 && b.rate < rate {
		rate = b.rate
	}
	b.rate = max(1, rate/2)
	if b.wait == 0 {
		b.wait = initialBackoff
	} else {
		b.wait = min(2*b.wait, maxBackoff)
	}
	b.hosts = append(b.hosts, target)
}

// sleep waits the backoff (canceled with ctx).
func (b *backoff) sleep(ctx context.Context) error {
	if b.wait <= 0 {
		return nil
	}
	t := time.NewTimer(b.wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// sleepFn waits a backoff (a var for tests).
var sleepFn = func(ctx context.Context, b *backoff) error { return b.sleep(ctx) }
