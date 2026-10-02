package content

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The default clients come from sdk-go httpsec: an untrusted (default,
// public) source cannot be made to reach a private or loopback address; a
// mirror the host operator configured (Trusted) can, as API_URL can.
func TestFetcherClientIsSSRFSafeUnlessHostConfigured(t *testing.T) {
	t.Setenv("OPENCTEM_SDK_ALLOW_LOOPBACK", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("rules: []\n"))
	}))
	defer srv.Close()

	untrusted := &Fetcher{AllowHTTP: true}
	if _, err := untrusted.get(context.Background(), srv.URL+"/r.yaml", 1<<20); err == nil {
		t.Fatal("default (untrusted) fetcher reached a loopback address")
	}

	trusted := &Fetcher{AllowHTTP: true, Trusted: true}
	body, err := trusted.get(context.Background(), srv.URL+"/r.yaml", 1<<20)
	if err != nil || !strings.Contains(string(body), "rules") {
		t.Fatalf("host-configured mirror refused: %v %q", err, body)
	}
}

func TestOCIResolverClientIsSSRFSafeUnlessHostConfigured(t *testing.T) {
	t.Setenv("OPENCTEM_SDK_ALLOW_LOOPBACK", "")
	const dg = "sha256:3b169afdc4a0862bcd1dd493d9fedb5ba26be377f9d541cb3fdde9e2bebadfab"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Docker-Content-Digest", dg)
	}))
	defer srv.Close()
	ref := OCIRef{Host: strings.TrimPrefix(srv.URL, "http://"), Repo: "aquasec/trivy-db", Tag: "2"}

	if _, err := (&OCIResolver{Scheme: "http"}).ResolveDigest(context.Background(), ref); err == nil {
		t.Fatal("default (untrusted) resolver reached a loopback registry")
	}
	got, err := (&OCIResolver{Scheme: "http", Trusted: true}).ResolveDigest(context.Background(), ref)
	if err != nil || got != dg {
		t.Fatalf("host-configured registry refused: %q %v", got, err)
	}
}
