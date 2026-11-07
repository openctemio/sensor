package lookup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeWaits(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	oldS, oldJ := Sleep, Jitter
	Sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	Jitter = func(max time.Duration) time.Duration { return max } // the longest wait
	t.Cleanup(func() { Sleep, Jitter = oldS, oldJ })
	return &waits
}

func tlsClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	old := HTTPClient
	HTTPClient = func(time.Duration) *http.Client { return srv.Client() }
	t.Cleanup(func() { HTTPClient = old })
	return NewClient(testManifest, nil, time.Second), srv
}

func age(t *testing.T, path string, d time.Duration) {
	t.Helper()
	ts := time.Now().Add(-d)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

// A failed refresh never fails a task while a copy exists, whatever its age;
// the copy is kept byte for byte and the failure is recorded.
func TestFetchKeepsAnyCopyWhenTheSourceFails(t *testing.T) {
	for _, status := range []int{502, 503, 429, 404} {
		c, srv := tlsClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		dir := t.TempDir()
		p := dir + "/d.bin"
		_ = os.WriteFile(p, []byte("old copy"), 0o600)
		age(t, p, 400*24*time.Hour)
		path, stale, err := c.Fetch(t.Context(), dir, Cached{Name: "d.bin", URL: srv.URL, MaxAge: time.Hour, AnyAge: true, MaxBytes: 1024})
		if path != p || !stale || err == nil {
			t.Fatalf("%d: %q %v %v", status, path, stale, err)
		}
		if b, _ := os.ReadFile(p); string(b) != "old copy" {
			t.Fatalf("%d: copy replaced: %q", status, b)
		}
		if m := ReadMeta(p); m.LastResult != "failed" || m.LastError != fmt.Sprintf("HTTP %d", status) {
			t.Fatalf("%d: meta %+v", status, m)
		}
	}
}

// 304 keeps the copy and renews its age; the validators of the copy are sent.
func TestFetchConditionalNotModified(t *testing.T) {
	var sawTag, sawSince atomic.Value
	c, srv := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		sawTag.Store(r.Header.Get("If-None-Match"))
		sawSince.Store(r.Header.Get("If-Modified-Since"))
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		_, _ = w.Write([]byte("content"))
	})
	dir := t.TempDir()
	f := Cached{Name: "d.bin", URL: srv.URL, MaxAge: time.Hour, AnyAge: true, MaxBytes: 1024}
	p, stale, err := c.Fetch(t.Context(), dir, f)
	if err != nil || stale {
		t.Fatal(err, stale)
	}
	if m := ReadMeta(p); m.ETag != `"v1"` || m.LastModified == "" || m.LastResult != "ok" {
		t.Fatalf("meta %+v", m)
	}
	age(t, p, 48*time.Hour)
	if _, stale, err := c.Fetch(t.Context(), dir, f); err != nil || stale {
		t.Fatalf("304: %v %v", stale, err)
	}
	if sawTag.Load() != `"v1"` || sawSince.Load() != "Mon, 02 Jan 2006 15:04:05 GMT" {
		t.Fatalf("validators not sent: %v %v", sawTag.Load(), sawSince.Load())
	}
	if a, _ := Age(p); a > time.Minute {
		t.Fatalf("mtime not renewed: %v", a)
	}
	if b, _ := os.ReadFile(p); string(b) != "content" {
		t.Fatalf("copy %q", b)
	}
	if m := ReadMeta(p); m.LastResult != "not_modified" || m.ETag != `"v1"` {
		t.Fatalf("meta %+v", m)
	}
}

// A download that does not validate (corrupt, too small) is not swapped in;
// the previous copy stays and the refresh counts as failed.
func TestFetchInvalidDownloadKeepsThePreviousCopy(t *testing.T) {
	c, srv := tlsClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("garbage")) })
	dir := t.TempDir()
	p := dir + "/d.bin"
	_ = os.WriteFile(p, []byte("good"), 0o600)
	age(t, p, 48*time.Hour)
	f := Cached{Name: "d.bin", URL: srv.URL, MaxAge: time.Hour, AnyAge: true, MaxBytes: 1024,
		Validate: func(path string) error {
			if b, _ := os.ReadFile(path); string(b) != "good" {
				return errors.New("not the expected file")
			}
			return nil
		}}
	path, stale, err := c.Fetch(t.Context(), dir, f)
	if path != p || !stale || err == nil || !strings.Contains(err.Error(), "previous copy is kept") {
		t.Fatalf("%q %v %v", path, stale, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "good" {
		t.Fatalf("copy replaced: %q", b)
	}
	if m := ReadMeta(p); m.LastResult != "failed" {
		t.Fatalf("meta %+v", m)
	}
	// No copy: the invalid download is an error, nothing is stored.
	dir2 := t.TempDir()
	if path, _, err := c.Fetch(t.Context(), dir2, f); path != "" || err == nil {
		t.Fatalf("invalid first download accepted: %q %v", path, err)
	}
	if ents, _ := os.ReadDir(dir2); len(ents) != 0 {
		t.Fatalf("leftovers %v", ents)
	}
}

// With no copy the download is retried with back-off, bounded.
func TestFetchFirstRunRetriesWithBoundedBackoff(t *testing.T) {
	waits := fakeWaits(t)
	var hits atomic.Int32
	c, srv := tlsClient(t, func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(502) })
	f := Cached{Name: "d.bin", URL: srv.URL, MaxAge: time.Hour, AnyAge: true, MaxBytes: 1024, Attempts: 4, Bound: 90 * time.Second}
	if p, _, err := c.Fetch(t.Context(), t.TempDir(), f); p != "" || err == nil {
		t.Fatalf("%q %v", p, err)
	}
	if hits.Load() != 4 || len(*waits) != 3 {
		t.Fatalf("attempts %d waits %v", hits.Load(), *waits)
	}
	var sum time.Duration
	for i, w := range *waits {
		sum += w
		if w <= 0 || w > 30*time.Second || (i > 0 && w < (*waits)[i-1]) {
			t.Fatalf("waits %v", *waits)
		}
	}
	if sum > 90*time.Second {
		t.Fatalf("waited %v", sum)
	}
	// With a copy there is exactly one attempt: the copy answers.
	hits.Store(0)
	dir := t.TempDir()
	_ = os.WriteFile(dir+"/d.bin", []byte("x"), 0o600)
	age(t, dir+"/d.bin", 48*time.Hour)
	if _, stale, _ := c.Fetch(t.Context(), dir, f); !stale || hits.Load() != 1 {
		t.Fatalf("stale %v hits %d", stale, hits.Load())
	}
}

// A refusal or a plain 4xx is final: no retries.
func TestFetchDoesNotRetryAFinalAnswer(t *testing.T) {
	waits := fakeWaits(t)
	var hits atomic.Int32
	c, srv := tlsClient(t, func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(403) })
	f := Cached{Name: "d.bin", URL: srv.URL, MaxAge: time.Hour, MaxBytes: 1024, Attempts: 4}
	_, _, _ = c.Fetch(t.Context(), t.TempDir(), f)
	f.URL = "http://mirror.example/d.bin"
	_, _, err := c.Fetch(t.Context(), t.TempDir(), f)
	if hits.Load() != 1 || len(*waits) != 0 || !errors.Is(err, ErrNotHTTPS) {
		t.Fatalf("hits %d waits %v err %v", hits.Load(), *waits, err)
	}
}

// Retry-After is honoured within the bound.
func TestFetchHonoursRetryAfterWithinTheBound(t *testing.T) {
	waits := fakeWaits(t)
	var hits atomic.Int32
	c, srv := tlsClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	f := Cached{Name: "d.bin", URL: srv.URL, MaxAge: time.Hour, MaxBytes: 1024, Attempts: 4, Bound: 90 * time.Second}
	if p, _, err := c.Fetch(t.Context(), t.TempDir(), f); p == "" || err != nil {
		t.Fatalf("%q %v", p, err)
	}
	if len(*waits) != 1 || (*waits)[0] != 7*time.Second {
		t.Fatalf("waits %v", *waits)
	}
	// A far larger Retry-After is cut to the bound.
	*waits = nil
	hits.Store(0)
	c2, srv2 := tlsClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(503)
	})
	f.URL = srv2.URL
	_, _, _ = c2.Fetch(t.Context(), t.TempDir(), f)
	var sum time.Duration
	for _, w := range *waits {
		sum += w
	}
	if sum > 90*time.Second || len(*waits) == 0 {
		t.Fatalf("waits %v", *waits)
	}
}

func TestLocalSourcesMustBeHTTPS(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := LocalFromEnv(env(map[string]string{EnvASNDatasetURL: "http://mirror.example/d.tsv.gz"})); !errors.Is(err, ErrNotHTTPS) {
		t.Fatalf("http dataset accepted: %v", err)
	}
	if _, err := LocalFromEnv(env(map[string]string{EnvRDAPBootstrapURL: "ftp://mirror.example/"})); !errors.Is(err, ErrNotHTTPS) {
		t.Fatalf("ftp bootstrap accepted: %v", err)
	}
	l, err := LocalFromEnv(env(map[string]string{EnvASNDatasetURL: "https://mirror.example/d.tsv.gz",
		EnvRDAPBootstrapURL: "https://mirror.example/rdap", EnvASNRDAPFallback: "OFF"}))
	if err != nil || !l.ASNRDAPFallbackOff || l.BootstrapURL("ipv4.json") != "https://mirror.example/rdap/ipv4.json" {
		t.Fatalf("%+v %v", l, err)
	}
	if d, _ := LocalFromEnv(env(nil)); d.BootstrapURL("dns.json") != "https://data.iana.org/rdap/dns.json" {
		t.Fatal("default bootstrap")
	}
}
