package tlscheck

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sensor/internal/tlscheck/tlstest"
)

func TestParseHostPort(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		host  string
		port  int
		plain bool
	}{
		{"a.example.test:443", true, "a.example.test", 443, false},
		{"a.example.test:80", true, "a.example.test", 80, true},
		{"192.0.2.7:8443", true, "192.0.2.7", 8443, false},
		{"[2001:db8::7]:443", true, "2001:db8::7", 443, false},
		{"a.example.test", true, "a.example.test", 443, false},
		{"https://a.example.test", false, "", 0, false},
		{"a.example.test:0", false, "", 0, false},
		{"a.example.test/x", false, "", 0, false},
		{"", false, "", 0, false},
		{"a b:443", false, "", 0, false},
	}
	for _, c := range cases {
		ep, ok := ParseHostPort(c.in)
		if ok != c.ok || (ok && (ep.Host != c.host || ep.Port != c.port || ep.Plain != c.plain)) {
			t.Errorf("%q: %+v %v", c.in, ep, ok)
		}
	}
}

// The classification table: a host that completes the handshake and resets
// the request, one that answers, one that refuses and one that does not
// answer, each with what its certificate shows.
func TestRecheckGapsClassifies(t *testing.T) {
	now := time.Now()
	reset := tlstest.Serve(t, tlstest.Reset, tlstest.Cert(t, "ssl.default.pagebuilder.test", now.Add(-800*24*time.Hour), now.Add(-400*24*time.Hour)))
	answer := tlstest.Serve(t, tlstest.Answer, tlstest.Cert(t, "localhost", now.Add(-time.Hour), now.Add(48*time.Hour)))
	closed := tlstest.ClosedPort(t)
	restore := SetDialerForTesting(tlstest.Direct)
	defer restore()

	gaps := []adapt.Gap{
		{Host: reset, Reason: adapt.GapBreakerOpen, Detail: "nuclei skipped the host after its error budget"},
		{Host: answer, Reason: adapt.GapBreakerOpen, Detail: "nuclei skipped the host after its error budget"},
		{Host: closed, Reason: adapt.GapBreakerOpen, Detail: "nuclei skipped the host after its error budget"},
		{Host: "localhost:1", Reason: adapt.GapBlocked, Detail: "edge"},
		{Host: "forwarder.example.test", Reason: adapt.GapBreakerOpen, Detail: "the host stopped answering"},
	}
	own := func(g adapt.Gap) bool { return g.Detail != "the host stopped answering" }
	got := RecheckGaps(context.Background(), gaps, own)

	want := []struct{ cause, cert string }{
		{adapt.GapCauseHTTPReset, adapt.GapCertExpired},
		{adapt.GapCauseAnswered, adapt.GapCertSelfSigned},
		{adapt.GapCauseRefused, ""},
		{"", ""}, // not a breaker gap: untouched
		{"", ""}, // not the tool's own gap: untouched
	}
	for i, w := range want {
		if got[i].Cause != w.cause || got[i].Cert != w.cert {
			t.Errorf("gap %d (%s): cause %q cert %q, want %q %q (detail %q)", i, got[i].Host, got[i].Cause, got[i].Cert, w.cause, w.cert, got[i].Detail)
		}
	}
	if got[0].Detail != "nuclei skipped the host after its error budget; recheck: TLS handshake completed, the HTTP request was reset; certificate expired" {
		t.Errorf("detail %q", got[0].Detail)
	}
	if got[3].Detail != "edge" || got[4].Detail != "the host stopped answering" {
		t.Errorf("untouched gaps changed: %+v", got[3:])
	}
}

// A probe that learns nothing (an offline dialer, a proxy refusal that
// names no upstream error) leaves the gap as the tool reported it.
func TestRecheckGapsLeavesUnknownAlone(t *testing.T) {
	restore := SetDialerForTesting(tlstest.Offline)
	defer restore()
	in := []adapt.Gap{{Host: "a.example.test:443", Reason: adapt.GapBreakerOpen, Detail: "d"}}
	got := RecheckGaps(context.Background(), in, nil)
	if got[0].Cause != "" || got[0].Cert != "" || got[0].Detail != "d" {
		t.Fatalf("got %+v", got[0])
	}
}

func TestProbeAllIsBounded(t *testing.T) {
	restore := SetDialerForTesting(tlstest.Offline)
	defer restore()
	eps := make([]Endpoint, MaxHosts+5)
	for i := range eps {
		eps[i] = Endpoint{Host: "a.example.test", Port: 443}
	}
	res := ProbeAll(context.Background(), eps, false)
	if len(res) != len(eps) {
		t.Fatalf("results %d", len(res))
	}
	for _, r := range res[MaxHosts:] {
		if r.Err != "" || r.Outcome != "" {
			t.Fatalf("an endpoint past the bound was probed: %+v", r)
		}
	}
	for _, r := range res[:MaxHosts] {
		if r.Err == "" {
			t.Fatalf("an endpoint within the bound was not probed: %+v", r)
		}
	}
}
