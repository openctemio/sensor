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

// The GitHub defaults are filled into the settings when the operator sets no
// nuclei URL. They must not make the source "host-configured": the trusted
// client refuses every redirect, and GitHub release downloads always redirect
// to release-assets.githubusercontent.com, so trusting the defaults broke
// every nuclei-templates refresh.
func TestNucleiDefaultSourceIsNotTrusted(t *testing.T) {
	cases := map[string]struct {
		env  map[string]string
		want bool
	}{
		"github defaults": {env: map[string]string{}, want: false},
		"host mirror":     {env: map[string]string{EnvNucleiURL: "https://mirror.internal/t.tar.gz"}, want: true},
		"host checksums":  {env: map[string]string{EnvNucleiChecksumsURL: "https://mirror.internal/c.txt"}, want: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := SettingsFromEnv(func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok })
			if err != nil {
				t.Fatal(err)
			}
			s.Enabled, s.Root = true, t.TempDir()
			m, err := NewFromSettings(s, Tools{Nuclei: true}, false)
			if err != nil {
				t.Fatal(err)
			}
			var n *NucleiTemplates
			for _, src := range m.sources {
				if v, ok := src.(*NucleiTemplates); ok {
					n = v
				}
			}
			if n == nil {
				t.Fatal("no nuclei source")
			}
			if n.Fetcher.Trusted != tc.want {
				t.Fatalf("Trusted = %v, want %v", n.Fetcher.Trusted, tc.want)
			}
		})
	}
}
