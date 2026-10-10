package lookup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var testManifest = tool.Manifest{Name: "t", Version: "1.0.0"}

// SECURITY: a passive lookup never reaches its own targets (or a host under
// a target name, or an address inside a target network), and never uses
// plain HTTP.
func TestClientRefusesTargetsAndPlainHTTP(t *testing.T) {
	c := NewClient(testManifest, []tool.Target{
		{Value: "example.com"}, {Value: "192.0.2.10"}, {Value: "198.51.100.0/24"}, {Value: "2001:db8::/32"},
	}, time.Second)
	for raw, want := range map[string]error{
		"https://example.com/x":               ErrTargetHost,
		"https://rdap.example.com/x":          ErrTargetHost,
		"https://EXAMPLE.com./x":              ErrTargetHost,
		"https://192.0.2.10/x":                ErrTargetHost,
		"https://198.51.100.77/x":             ErrTargetHost,
		"https://[2001:db8::1]/x":             ErrTargetHost,
		"http://rdap.registry.test/x":         ErrNotHTTPS,
		"https://rdap.registry.test/x":        nil,
		"https://notexample.com/x":            nil,
		"https://203.0.113.1/x":               nil,
		"https://data.iana.org/rdap/dns.json": nil,
	} {
		u, _ := url.Parse(raw)
		if got := c.allowed(u); !errors.Is(got, want) {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}

// SECURITY: a redirect to a target is refused like a direct request.
func TestClientRefusesARedirectToATarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com/rdap", http.StatusFound)
	}))
	defer srv.Close()
	old := HTTPClient
	HTTPClient = func(time.Duration) *http.Client { return srv.Client() }
	defer func() { HTTPClient = old }()
	c := NewClient(testManifest, []tool.Target{{Value: "example.com"}}, time.Second)
	if _, err := c.Get(context.Background(), srv.URL+"/domain/example.com", ""); !errors.Is(err, ErrTargetHost) {
		t.Fatalf("redirect followed: %v", err)
	}
}

func TestClientBoundsAnswers(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/429" {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write(make([]byte, 64))
	}))
	defer srv.Close()
	old := HTTPClient
	HTTPClient = func(time.Duration) *http.Client { return srv.Client() }
	defer func() { HTTPClient = old }()
	c := NewClient(testManifest, nil, time.Second)
	c.maxBody = 32
	if _, err := c.Get(context.Background(), srv.URL+"/big", ""); err == nil {
		t.Fatal("an answer above the limit was accepted")
	}
	var se *StatusError
	if _, err := c.Get(context.Background(), srv.URL+"/429", ""); !errors.As(err, &se) || se.Code != 429 || se.RetryAfter != 7*time.Second {
		t.Fatalf("429: %v", err)
	}
	// Fetch caches: a fresh copy is not downloaded again; a failed
	// download keeps the previous copy.
	dir := t.TempDir()
	f := Cached{Name: "d.bin", URL: srv.URL + "/d", MaxAge: time.Hour, MaxStale: 2 * time.Hour, MaxBytes: 1024}
	if p, stale, err := c.Fetch(context.Background(), dir, f); err != nil || stale || p == "" {
		t.Fatalf("fetch %q %v %v", p, stale, err)
	}
	f.URL = srv.URL + "/429"
	if _, stale, err := c.Fetch(context.Background(), dir, f); err != nil || stale {
		t.Fatalf("fresh copy re-downloaded: %v %v", stale, err)
	}
	old2 := time.Now().Add(-90 * time.Minute)
	_ = os.Chtimes(dir+"/d.bin", old2, old2)
	if p, stale, err := c.Fetch(context.Background(), dir, f); p == "" || !stale || err == nil {
		t.Fatalf("stale fallback %q %v %v", p, stale, err)
	}
	f.MaxBytes = 16
	f.URL = srv.URL + "/d"
	f.MaxStale = time.Minute
	if p, _, err := c.Fetch(context.Background(), dir, f); p != "" || err == nil {
		t.Fatalf("oversized download accepted: %q %v", p, err)
	}
}

func TestScannerRefusesExtraArgs(t *testing.T) {
	m := tool.Manifest{APIVersion: tool.APIVersion, Name: "xt", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
		Consumes: []string{"domain"}, Produces: []string{"asset:domain"}}
	s := New(Spec{Tool: tool.New(m, func(tool.Context, tool.Task, tool.NoConfig) error { return nil }),
		Schema: core.MustParseSettingsSchema(`{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{}}`)})
	s.CacheRoot = t.TempDir()
	if _, err := s.Scan(context.Background(), "example.com", &core.ScanOptions{ExtraArgs: []string{"-x"}}); !errors.Is(err, ErrExtraArgs) {
		t.Fatalf("extra args: %v", err)
	}
	if d := s.cacheDir(); d == "" {
		t.Fatal("no cache dir")
	} else if st, err := os.Stat(d); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir mode %v %v", st, err)
	}
}
