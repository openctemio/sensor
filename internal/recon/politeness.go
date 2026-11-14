package recon

// Politeness and host-bound traffic for the recon tools (api
// docs/rfcs/RFC-036-easm.md §6.13; research/22 P0-2 in openctemio/openctem).
//
//   - Rate: a scan's rate_limit / concurrency (core.ScanOptions, already
//     capped by the local policy's rate.max_rps) reach the tool, and only
//     lower the tool's own limits. Before, the wrapper dropped them, so
//     recon ran at the tools' defaults whatever the scan or the sensor
//     owner asked.
//   - Pacing: a rate or concurrency no person chose runs at the pacing level
//     (toolrun.Pacing, research 518 D1), mapped per tool (PacedLimits):
//     httpx 50/s over 25 threads, katana 20/s and 8 at once, naabu 300
//     packets/s at Standard. A job's cap and the local policy still lower it.
//   - Backoff: a target that answers 429 Too Many Requests or 503, or sends
//     a Retry-After, halves the rate of the job's later targets (down to 1
//     request/s) and waits before the next one, at least its Retry-After
//     (capped at adapt.TargetRate.RetryAfterMax).
//   - Throttle marks: every such target, in a serial loop or a batch run
//     over the whole list (httpx), is counted (adapt.ThrottleTally) and
//     reported as a coverage gap "throttled" with its counts: its outcome
//     in metadata.targets is rate limited, the run is partial, and the
//     sensor logs one line per run with the totals. Its records are still
//     kept. No rotation or evasion (RFC-034).
//   - Host-bound: extra args can never widen where a tool goes (follow
//     redirects to other hosts, widen or drop katana's scope).

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
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

// pacedTool is a recon tool that maps the pacing level to its own rate and
// concurrency.
type pacedTool interface {
	PacedLimits(adapt.Pacing) toolrun.PacedLimits
}

// observeThrottle counts target's push-back answers in r (429 Too Many
// Requests, 503 Service Unavailable, or a Retry-After) and reports whether
// there was any.
func observeThrottle(tally *adapt.ThrottleTally, target string, r *core.ReconResult) bool {
	if r == nil {
		return false
	}
	hit := false
	for _, h := range r.LiveHosts {
		hit = tally.Observe(target, h.StatusCode, h.RetryAfter) || hit
	}
	for _, u := range r.URLs {
		hit = tally.Observe(target, u.StatusCode, 0) || hit
	}
	return hit
}

// logThrottle writes one line per run that met push-back: the counts and
// the longest Retry-After, never a target or anything it sent.
func logThrottle(ctx context.Context, tool string, tally *adapt.ThrottleTally) {
	n, tooMany, unavailable, retryAfter := tally.Summary()
	if n == 0 {
		return
	}
	log := slog.Default()
	if lc, ok := ctx.(interface{ Log() *slog.Logger }); ok && lc.Log() != nil {
		// A tool child's log reaches the sensor's.
		log = lc.Log()
	}
	log.InfoContext(ctx, "targets throttled the scan", "tool", tool, "targets", n,
		"answers_429", tooMany, "answers_503", unavailable, "retry_after_max", retryAfter.String())
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
// the wait (at most maxBackoff), never shorter than the longest Retry-After
// seen (already capped).
func (b *backoff) hit(target string, rate int, retryAfter time.Duration) {
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
	b.wait = max(b.wait, retryAfter)
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
