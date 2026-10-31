package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sensor/internal/reachobs"
	"github.com/openctemio/sensor/internal/tlscheck"
)

// TLS facts of a host that does not answer HTTP.
//
// httpx takes the certificate from the HTTP response, so a host that
// completes the TLS handshake and then resets every request (often a host
// whose certificate expired, or one that serves another site's default
// certificate) is a failed line with no certificate. For each such https
// URL (the failure says the host answered: a reset, a closed connection, a
// TLS error) the probe reads the certificate itself (tlscheck, one
// handshake, no request) and the result gets a live host with status 0 and
// the certificate: the platform records the service and the certificate it
// served, and judges the certificate (expired, names that do not cover the
// host), even though no HTTP answer came.

// tlsOnlyCandidate is one failed https URL of httpx's output.
type tlsOnlyCandidate struct {
	result *core.ReconResult
	out    HTTPXOutput
	ep     tlscheck.Endpoint
}

// addTLSOnly adds to each result a live host with the certificate of every
// https URL that failed after the host answered. It does nothing without
// -tls-grab (the scan did not ask for certificates).
func (s *Scanner) addTLSOnly(ctx context.Context, results ...*core.ReconResult) {
	if !s.TLSGrab {
		return
	}
	var cands []tlsOnlyCandidate
	for _, r := range results {
		if r == nil {
			continue
		}
		cands = append(cands, tlsOnlyCandidates(r)...)
		if len(cands) >= tlscheck.MaxHosts {
			cands = cands[:tlscheck.MaxHosts]
			break
		}
	}
	if len(cands) == 0 {
		return
	}
	eps := make([]tlscheck.Endpoint, len(cands))
	for i, c := range cands {
		eps[i] = c.ep
	}
	probes := tlscheck.ProbeAll(ctx, eps, false)
	for i, c := range cands {
		p := probes[i]
		if p.Leaf == nil {
			continue
		}
		ip := p.RemoteAddr
		if ip == "" {
			ip = c.out.HostIP
		}
		if ip == "" && len(c.out.A) > 0 {
			ip = c.out.A[0]
		}
		c.result.LiveHosts = append(c.result.LiveHosts, core.LiveHost{
			URL:        c.out.URL,
			Host:       c.ep.Host,
			IP:         ip,
			Port:       c.ep.Port,
			Scheme:     "https",
			StatusCode: 0, // no HTTP answer
			TLSVersion: p.TLSVersion,
			TLS:        p.Leaf,
			CNAMEs:     core.SanitizeCNAMEs(c.out.CNAMEs),
		})
	}
}

// tlsOnlyCandidates are the failed https URLs of r's output whose failure
// says the host answered, once each, minus URLs r already has as live
// hosts.
func tlsOnlyCandidates(r *core.ReconResult) []tlsOnlyCandidate {
	if len(r.RawOutput) == 0 {
		return nil
	}
	have := make(map[string]bool, len(r.LiveHosts))
	for _, h := range r.LiveHosts {
		have[h.URL] = true
	}
	var out []tlsOnlyCandidate
	sc := bufio.NewScanner(bytes.NewReader(r.RawOutput))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var o HTTPXOutput
		if json.Unmarshal(line, &o) != nil || !o.Failed || have[o.URL] {
			continue
		}
		if reachobs.Classify(o.Error) != reach.Reached {
			continue
		}
		u, err := url.Parse(o.URL)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
			continue
		}
		port := urlPort(o)
		if port == 0 {
			continue
		}
		have[o.URL] = true
		out = append(out, tlsOnlyCandidate{result: r, out: o, ep: tlscheck.Endpoint{Host: u.Hostname(), Port: port}})
	}
	return out
}
