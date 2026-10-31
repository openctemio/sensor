// Package tlscheck is the sensor's use of sdk-go pkg/tlsprobe: it reads the
// certificate of a host whose HTTP requests failed, and rechecks the hosts
// a tool gave up, so the result says what the host did (it completed the
// TLS handshake and reset the request, failed the handshake, refused, did
// not answer) and which certificate it served, instead of "stopped
// answering".
//
// Every probe dials the way the task's tools do: through the task's egress
// proxy in a confined run (egressenv.Proxy), so the local policy, the
// target scope and the per-host rate apply; directly otherwise, as the
// tools themselves do. The hosts come from the tool's own output for the
// task's targets; each gets one handshake and at most one HEAD request, a
// bounded number of hosts per run and a bounded time in all.
package tlscheck

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/tlsprobe"
	"github.com/openctemio/sensor/internal/egressenv"
)

// Bounds.
const (
	// MaxHosts is how many hosts one run probes; the rest keep what the
	// tool said.
	MaxHosts = 32
	// parallel probes at once.
	parallel = 4
	// stepTimeout bounds each step of a probe (connect, handshake,
	// response head).
	stepTimeout = 8 * time.Second
	// budget bounds all the probes of one run.
	budget = 90 * time.Second
)

// dialer is the probes' DialFunc; tests replace it.
var dialer = func() (tlsprobe.DialFunc, error) { return tlsprobe.Dialer(egressenv.Proxy()) }

// Endpoint is one host and port to probe.
type Endpoint struct {
	Host  string
	Port  int
	Plain bool // no TLS: an http:// URL
}

// ParseHostPort reads a tool's "host:port" (or a bare host, port 443) as an
// endpoint. ok is false for anything else (a URL, a path, an empty name).
func ParseHostPort(s string) (Endpoint, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "/?#@ \t") {
		return Endpoint{}, false
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return Endpoint{Host: ap.Addr().String(), Port: int(ap.Port())}, ap.Port() > 0
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || h == "" {
			return Endpoint{}, false
		}
		return Endpoint{Host: h, Port: n, Plain: n == 80}, true
	}
	if strings.Contains(s, ":") && net.ParseIP(strings.Trim(s, "[]")) == nil {
		return Endpoint{}, false
	}
	return Endpoint{Host: strings.Trim(s, "[]"), Port: 443}, true
}

// ProbeAll probes each endpoint (at most MaxHosts, parallel, within the
// run budget) and returns the results in the same order; an endpoint past
// the bound or the budget gets an empty result. withHTTP sends one HEAD
// request after the handshake.
func ProbeAll(ctx context.Context, eps []Endpoint, withHTTP bool) []tlsprobe.Result {
	out := make([]tlsprobe.Result, len(eps))
	if len(eps) == 0 {
		return out
	}
	dial, err := dialer()
	if err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, ep := range eps {
		if i >= MaxHosts {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			out[i] = tlsprobe.Probe(ctx, dial, ep.Host, ep.Port, tlsprobe.Options{
				HTTP: withHTTP, Plain: ep.Plain, Timeout: stepTimeout,
			})
		}()
	}
	wg.Wait()
	return out
}

// RecheckGaps rechecks the hosts a tool gave up (Reason breaker_open, Host
// "host:port"; select picks which gaps are the tool's own) and sets each
// one's Cause and Cert from what the host did, with a short note on its
// Detail. A gap the probe learned nothing about is left as it was.
func RecheckGaps(ctx context.Context, gaps []adapt.Gap, own func(adapt.Gap) bool) []adapt.Gap {
	var idx []int
	var eps []Endpoint
	for i, g := range gaps {
		if g.Reason != adapt.GapBreakerOpen || (own != nil && !own(g)) {
			continue
		}
		ep, ok := ParseHostPort(g.Host)
		if !ok {
			continue
		}
		idx = append(idx, i)
		eps = append(eps, ep)
		if len(eps) == MaxHosts {
			break
		}
	}
	if len(eps) == 0 {
		return gaps
	}
	res := ProbeAll(ctx, eps, true)
	now := time.Now()
	for k, i := range idx {
		r := res[k]
		if r.Outcome == tlsprobe.OutcomeUnknown {
			continue
		}
		g := &gaps[i]
		g.Cause = r.Outcome
		g.Cert = r.CertProblem(now)
		if note := recheckNote(r, g.Cert); note != "" {
			g.Detail = strings.TrimSpace(g.Detail + "; recheck: " + note)
		}
	}
	return gaps
}

// recheckNote is what the recheck saw, in a few words.
func recheckNote(r tlsprobe.Result, cert string) string {
	var b strings.Builder
	switch r.Outcome {
	case tlsprobe.OutcomeHTTPReset:
		if r.Leaf != nil {
			b.WriteString("TLS handshake completed, the HTTP request was reset")
		} else {
			b.WriteString("the connection opened, the HTTP request was reset")
		}
	case tlsprobe.OutcomeTLSFailed:
		b.WriteString("the connection opened, the TLS handshake failed")
	case tlsprobe.OutcomeReset:
		b.WriteString("the connection was reset")
	case tlsprobe.OutcomeRefused:
		b.WriteString("connection refused")
	case tlsprobe.OutcomeNoAnswer:
		b.WriteString("no answer")
	case tlsprobe.OutcomeAnswered:
		b.WriteString("the host answered (HTTP " + strconv.Itoa(r.Status) + ")")
	default:
		return ""
	}
	if cert != "" {
		b.WriteString("; certificate " + strings.ReplaceAll(cert, "_", " "))
	}
	return b.String()
}

// SetDialerForTesting makes every probe dial with d and returns the
// function that restores the default. For tests only: a package whose
// tests run a tool that reports gaps sets a dialer that never connects.
func SetDialerForTesting(d tlsprobe.DialFunc) (restore func()) {
	prev := dialer
	dialer = func() (tlsprobe.DialFunc, error) { return d, nil }
	return func() { dialer = prev }
}
