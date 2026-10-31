package httpx

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/tlscheck"
	"github.com/openctemio/sensor/internal/tlscheck/tlstest"
)

func TestMain(m *testing.M) {
	// No test of this package dials out for a certificate unless it sets
	// its own dialer.
	tlscheck.SetDialerForTesting(tlstest.Offline)
	os.Exit(m.Run())
}

// httpx reports a host that completes the handshake and resets the request
// as failed, without a certificate. The result still gets the host's
// certificate, on a live host with status 0 (no HTTP answer).
func TestFailedHTTPSKeepsTheCertificate(t *testing.T) {
	now := time.Now()
	host := tlstest.Serve(t, tlstest.Reset, tlstest.Cert(t, "ssl.default.pagebuilder.test", now.Add(-800*24*time.Hour), now.Add(-400*24*time.Hour)))
	closed := tlstest.ClosedPort(t)
	restore := tlscheck.SetDialerForTesting(tlstest.Direct)
	defer restore()

	raw := `{"input":"a","url":"https://` + host + `","error":"connection reset by peer","status_code":0,"failed":true}
{"input":"a","url":"https://` + closed + `","error":"dial tcp: connect: connection refused","failed":true}
{"input":"a","url":"http://` + host + `","error":"connection reset by peer","failed":true}
{"input":"a","url":"https://` + host + `","error":"connection reset by peer","failed":true}
`
	s := NewScanner()
	s.TLSGrab = true
	r := &core.ReconResult{RawOutput: []byte(raw)}
	s.addTLSOnly(context.Background(), r)
	if len(r.LiveHosts) != 1 {
		t.Fatalf("live hosts %+v, want one (the https URL whose host answered, once)", r.LiveHosts)
	}
	h := r.LiveHosts[0]
	if h.StatusCode != 0 || h.Scheme != "https" || h.Host != "localhost" || h.IP != "127.0.0.1" || h.TLS == nil {
		t.Fatalf("live host %+v", h)
	}
	if !h.TLS.Expired || !h.TLS.Mismatched || h.TLS.SubjectCN != "ssl.default.pagebuilder.test" || len(h.TLS.FingerprintSHA256) != 64 {
		t.Fatalf("certificate %+v", h.TLS)
	}

	// Without -tls-grab the scan did not ask for certificates.
	s.TLSGrab = false
	r = &core.ReconResult{RawOutput: []byte(raw)}
	s.addTLSOnly(context.Background(), r)
	if len(r.LiveHosts) != 0 {
		t.Fatalf("probed without -tls-grab: %+v", r.LiveHosts)
	}
}

// A URL httpx already reported live is not probed again; a failure that
// says nothing answered (a timeout) is not a candidate.
func TestTLSOnlyCandidates(t *testing.T) {
	raw := `{"input":"a","url":"https://a.example.test","status_code":200}
{"input":"a","url":"https://a.example.test","error":"connection reset by peer","failed":true}
{"input":"a","url":"https://b.example.test","error":"context deadline exceeded (Client.Timeout exceeded)","failed":true}
{"input":"a","url":"https://c.example.test:8443","error":"EOF","failed":true}
`
	r := &core.ReconResult{RawOutput: []byte(raw), LiveHosts: []core.LiveHost{{URL: "https://a.example.test"}}}
	c := tlsOnlyCandidates(r)
	if len(c) != 1 || c[0].ep.Host != "c.example.test" || c[0].ep.Port != 8443 {
		t.Fatalf("candidates %+v", c)
	}
}
