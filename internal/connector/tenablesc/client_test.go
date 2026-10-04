package tenablesc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_PaginationExclusiveEndOffset(t *testing.T) {
	f := newFakeSC(t)
	inst := f.instance()
	c := f.client(t, inst, nil)
	q := Query{Tool: "vulndetails", SourceType: "cumulative"}

	p1, err := c.Analysis(context.Background(), q, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Total != 3 || len(p1.Results) != 2 {
		t.Fatalf("page 1: total %d, %d results", p1.Total, len(p1.Results))
	}
	p2, err := c.Analysis(context.Background(), q, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Results) != 1 {
		t.Fatalf("page 2: %d results, want 1", len(p2.Results))
	}
	qs, _ := f.recorded()
	if qs[0].Query.StartOffset != 0 || qs[0].Query.EndOffset != 2 || qs[1].Query.StartOffset != 2 || qs[1].Query.EndOffset != 4 {
		t.Fatalf("offsets: %+v", qs)
	}
	if qs[0].Type != "vuln" || qs[0].SourceType != "cumulative" || qs[0].Query.Tool != "vulndetails" {
		t.Fatalf("query shape: %+v", qs[0])
	}
}

func TestClient_PageLargerThanAskedIsRefused(t *testing.T) {
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if r.URL.Path != "/rest/analysis" {
			return false
		}
		writeEnvelope(w, 200, map[string]any{"totalRecords": "3", "results": []any{map[string]any{}, map[string]any{}, map[string]any{}}})
		return true
	})
	c := f.client(t, f.instance(), nil)
	if _, err := c.Analysis(context.Background(), Query{Tool: "vulndetails", SourceType: "cumulative"}, 0, 2); err == nil {
		t.Fatal("a page with more results than asked must fail")
	}
}

func TestClient_ErrorCodeWith200(t *testing.T) {
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		writeError(w, 200, 143, strings.Repeat("x", 2000))
		return true
	})
	c := f.client(t, f.instance(), nil)
	_, err := c.System(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 143 {
		t.Fatalf("want APIError 143, got %v", err)
	}
	if len(apiErr.Msg) > maxErrorMsgBytes {
		t.Fatalf("message not capped: %d bytes", len(apiErr.Msg))
	}
}

func TestClient_403IsForbiddenAndNotRetried(t *testing.T) {
	f := newFakeSC(t)
	var calls atomic.Int32
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		calls.Add(1)
		writeError(w, 403, 2, "You do not have permission")
		return true
	})
	c := f.client(t, f.instance(), nil)
	_, err := c.System(context.Background())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("403 retried: %d calls", calls.Load())
	}
}

func TestClient_401IsNotRetried(t *testing.T) {
	f := newFakeSC(t)
	inst := f.instance()
	inst.SecretKey = Secret{"wrongwrongwrongwrong"}
	var sleeps []time.Duration
	c := f.client(t, inst, &sleeps)
	_, err := c.System(context.Background())
	if !errors.Is(err, ErrCredentialsRejected) {
		t.Fatalf("want ErrCredentialsRejected, got %v", err)
	}
	if f.badKeyCount() != 1 || len(sleeps) != 0 {
		t.Fatalf("401 retried: %d requests, %d sleeps", f.badKeyCount(), len(sleeps))
	}
	if strings.Contains(err.Error(), "wrongwrong") || strings.Contains(err.Error(), testAccessKey) {
		t.Fatal("error leaks a key")
	}
}

func TestClient_429RetryAfterThenSuccess(t *testing.T) {
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, n int) bool {
		if n <= 2 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return true
		}
		return false
	})
	var sleeps []time.Duration
	c := f.client(t, f.instance(), &sleeps)
	sys, err := c.System(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sys.Version != "6.4.0" {
		t.Fatalf("version %q", sys.Version)
	}
	if len(sleeps) != 2 || sleeps[0] != 7*time.Second {
		t.Fatalf("sleeps %v, want two of 7s", sleeps)
	}
}

func TestClient_RetryAfterIsCapped(t *testing.T) {
	if d := parseRetryAfter("3600"); d != maxRetryAfter {
		t.Fatalf("Retry-After 3600 → %v, want %v", d, maxRetryAfter)
	}
}

func TestClient_503ExhaustsRetries(t *testing.T) {
	f := newFakeSC(t)
	var calls atomic.Int32
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	var sleeps []time.Duration
	c := f.client(t, f.instance(), &sleeps)
	_, err := c.System(context.Background())
	if err == nil || !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("want give-up error, got %v", err)
	}
	if calls.Load() != maxAttempts || len(sleeps) != maxAttempts-1 {
		t.Fatalf("%d calls, %d sleeps", calls.Load(), len(sleeps))
	}
	for _, d := range sleeps {
		if d > maxBackoff {
			t.Fatalf("backoff %v above cap", d)
		}
	}
}

func TestClient_BodyOverCap(t *testing.T) {
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		writeEnvelope(w, 200, map[string]any{"version": strings.Repeat("9", 2<<20)})
		return true
	})
	c := f.client(t, f.instance(), nil) // cap 1 MiB
	if _, err := c.System(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

func TestClient_MalformedJSON(t *testing.T) {
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"regular","response":{"totalRecords":"3","results":[{"pluginID":"1"`))
		return true
	})
	c := f.client(t, f.instance(), nil)
	_, err := c.Analysis(context.Background(), Query{Tool: "vulndetails", SourceType: "cumulative"}, 0, 2)
	if err == nil || !strings.Contains(err.Error(), "malformed JSON") {
		t.Fatalf("want malformed JSON error, got %v", err)
	}
}

func TestClient_UnsupportedVersion(t *testing.T) {
	f := newFakeSC(t)
	f.version = "5.12.1"
	c := f.client(t, f.instance(), nil)
	if _, err := c.System(context.Background()); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestClient_RedirectRefusedKeyNotSent(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "" {
			leaked.Add(1)
		}
		writeEnvelope(w, 200, map[string]any{"version": "6.4.0"})
	}))
	defer other.Close()
	f := newFakeSC(t)
	f.setIntercept(func(w http.ResponseWriter, r *http.Request, _ int) bool {
		http.Redirect(w, r, other.URL+"/rest/system", http.StatusFound)
		return true
	})
	c := f.client(t, f.instance(), nil)
	if _, err := c.System(context.Background()); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("want ErrRedirectRefused, got %v", err)
	}
	if leaked.Load() != 0 {
		t.Fatal("the API key was sent to the redirect target")
	}
}

func TestClient_WrongCARefused(t *testing.T) {
	f := newFakeSC(t)
	inst := f.instance()
	inst.CAPEM = otherCAPEM(t) // trusts a CA that did not sign the server's certificate
	c := f.client(t, inst, nil)
	_, err := c.System(context.Background())
	if err == nil || !strings.Contains(err.Error(), "TLS verification failed") {
		t.Fatalf("want TLS verification failure, got %v", err)
	}
	if _, reqs := f.recorded(); f.badKeyCount() != 0 || len(reqs) != 0 {
		t.Fatal("a request reached the server through an untrusted connection")
	}
}

func TestClient_PinMismatchRefused(t *testing.T) {
	f := newFakeSC(t)
	inst := f.instance()
	bad := sha256.Sum256([]byte("not the key"))
	inst.Pins = [][]byte{bad[:]}
	c := f.client(t, inst, nil)
	if _, err := c.System(context.Background()); err == nil {
		t.Fatal("a pin mismatch must fail")
	}
	good := sha256.Sum256(f.srv.Certificate().RawSubjectPublicKeyInfo)
	inst.Pins = [][]byte{bad[:], good[:]}
	if _, err := f.client(t, inst, nil).System(context.Background()); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
}

func TestClient_LoopbackBlockedInProduction(t *testing.T) {
	f := newFakeSC(t)
	c, err := NewClient(f.instance())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.System(context.Background()); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("production client reached loopback: %v", err)
	}
}

func TestClient_PluginIDValidated(t *testing.T) {
	f := newFakeSC(t)
	c := f.client(t, f.instance(), nil)
	if _, err := c.Plugin(context.Background(), "../system"); err == nil {
		t.Fatal("a non-numeric plugin id must be refused before any request")
	}
	if _, reqs := f.recorded(); len(reqs) != 0 {
		t.Fatalf("requests sent: %v", reqs)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := Secret{"supersecret"}
	for _, out := range []string{s.String(), s.GoString()} {
		if strings.Contains(out, "supersecret") {
			t.Fatal("secret printed")
		}
	}
}

// otherCAPEM is a fresh self-signed CA unrelated to the test server.
func otherCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "other CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
