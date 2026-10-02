package content

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

const testDigest = "sha256:3b169afdc4a0862bcd1dd493d9fedb5ba26be377f9d541cb3fdde9e2bebadfab"

// fakeRegistry answers manifest HEADs behind an anonymous bearer challenge.
func fakeRegistry(t *testing.T, repos map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.URL.Query().Get("scope") == "" || r.URL.Query().Get("service") != "fake" {
				http.Error(w, "bad scope", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token":"tok"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="fake",scope="repository:x:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.manifest.v1+json") {
			http.Error(w, "accept", http.StatusNotAcceptable)
			return
		}
		repo, ref, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/")
		dg, ok := repos[repo]
		if !ok || (ref != "2" && ref != dg) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", dg)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOCIResolverBearerFlow(t *testing.T) {
	srv := fakeRegistry(t, map[string]string{"aquasec/trivy-db": testDigest})
	host := strings.TrimPrefix(srv.URL, "http://")
	r := &OCIResolver{Scheme: "http"}
	ref, err := ParseOCIRef(host + "/aquasec/trivy-db:2")
	if err != nil {
		t.Fatal(err)
	}
	dg, err := r.ResolveDigest(context.Background(), ref)
	if err != nil || dg != testDigest {
		t.Fatalf("digest %q %v", dg, err)
	}
	if _, err := r.ResolveDigest(context.Background(), OCIRef{Host: host, Repo: "missing/repo", Tag: "2"}); err == nil {
		t.Fatal("missing repository resolved")
	}
}

func TestParseOCIRef(t *testing.T) {
	r, err := ParseOCIRef("ghcr.io/aquasecurity/trivy-db@" + testDigest)
	if err != nil || r.Digest != testDigest || r.Repo != "aquasecurity/trivy-db" || r.String() != "ghcr.io/aquasecurity/trivy-db@"+testDigest {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{"trivy-db:2", "ghcr.io/", "ghcr.io/x@sha256:zz", "-x.io/a", "ghcr.io/../x"} {
		if _, err := ParseOCIRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	s, p := parseChallenge(`Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull"`)
	if s != "Bearer" || p["realm"] != "https://ghcr.io/token" || p["service"] != "ghcr.io" || p["scope"] != "repository:a/b:pull" {
		t.Fatalf("%s %v", s, p)
	}
}

// fakeTrivy writes a database for --download-db-only (failing for any
// repository containing "broken") and reports it for `version`.
func fakeTrivy(t *testing.T, updatedAt string) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "trivy")
	log = filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$@" >> "` + log + `"
cache=""; repo=""; mode="$1"; java=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cache-dir) cache="$2"; shift ;;
    --db-repository) repo="$2"; shift ;;
    --download-java-db-only) java=1 ;;
  esac
  shift
done
if [ "$mode" = "image" ]; then
  case "$repo" in *broken*) echo "FATAL download failed" >&2; exit 1 ;; esac
  if [ -n "$java" ]; then mkdir -p "$cache/java-db"; echo '{"Version":1,"UpdatedAt":"2026-09-30T00:00:00Z"}' > "$cache/java-db/metadata.json"; exit 0; fi
  mkdir -p "$cache/db"; echo db > "$cache/db/trivy.db"
  echo '{"Version":2,"UpdatedAt":"` + updatedAt + `"}' > "$cache/db/metadata.json"
  exit 0
fi
if [ "$mode" = "version" ]; then
  printf '{"Version":"0.69.3","VulnerabilityDB":%s' "$(cat "$cache/db/metadata.json")"
  if [ -f "$cache/java-db/metadata.json" ]; then printf ',"JavaDB":%s' "$(cat "$cache/java-db/metadata.json")"; fi
  echo '}'
  exit 0
fi
exit 2
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	return bin, log
}

func TestTrivyDBRefreshPinsDigestAndFallsThrough(t *testing.T) {
	srv := fakeRegistry(t, map[string]string{"aquasec/trivy-db": testDigest})
	host := strings.TrimPrefix(srv.URL, "http://")
	bin, log := fakeTrivy(t, "2026-10-02T01:05:41Z")
	root := t.TempDir()
	src := &TrivyDB{
		Binary: bin, Root: root, Resolver: &OCIResolver{Scheme: "http"},
		// The first repository does not have the database: the second answers.
		Repositories: []string{host + "/missing/trivy-db:2", host + "/aquasec/trivy-db:2"},
	}
	m, err := New(Config{Root: root, Logf: t.Logf}, src)
	if err != nil {
		t.Fatal(err)
	}
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil || !res[0].Refreshed {
		t.Fatalf("refresh %+v", res)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "--db-repository "+host+"/aquasec/trivy-db@"+testDigest) {
		t.Fatalf("download not pinned to the digest: %s", calls)
	}
	h := m.Acquire(core.ContentTrivyDB)
	defer h.Release()
	if h.Meta.Digest != testDigest || h.Meta.Version != "2026-10-02T01:05:41Z" || h.Meta.UpdatedAt == nil {
		t.Fatalf("meta %+v", h.Meta)
	}
	// Without a managed Java DB the version links the shared one.
	if target, err := os.Readlink(filepath.Join(h.Dir, "java-db")); err != nil || target != filepath.Join(root, core.ContentTrivyDB, sharedJavaDB) {
		t.Fatalf("java-db link %q %v", target, err)
	}

	// Unchanged digest: no second download.
	before, _ := os.ReadFile(log)
	res = m.Refresh(context.Background(), nil, false)
	after, _ := os.ReadFile(log)
	if !res[0].Unchanged || string(before) != string(after) {
		t.Fatalf("unchanged digest downloaded again: %+v", res)
	}
}

func TestTrivyDBNoDigestFallsBackToTags(t *testing.T) {
	bin, log := fakeTrivy(t, "2026-10-02T01:05:41Z")
	src := &TrivyDB{
		Binary: bin, Resolver: &OCIResolver{Scheme: "http"},
		Repositories: []string{"127.0.0.1:1/broken/trivy-db:2", "127.0.0.1:1/aquasec/trivy-db:2"},
	}
	m := newTestManager(t, src)
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil {
		t.Fatalf("refresh %+v", res)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "127.0.0.1:1/aquasec/trivy-db:2") {
		t.Fatalf("second repository not tried: %s", calls)
	}
	h := m.Acquire(core.ContentTrivyDB)
	defer h.Release()
	if h.Meta.Digest != "" || h.Meta.Version == "" {
		t.Fatalf("meta %+v", h.Meta)
	}
}

func TestTrivyDBVerifyRejectsWrongSchema(t *testing.T) {
	bin, _ := fakeTrivy(t, "2026-10-02T01:05:41Z")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "db"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "db", "trivy.db"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "db", "metadata.json"), []byte(`{"Version":1,"UpdatedAt":"2026-10-02T00:00:00Z"}`), 0o644)
	if err := (&TrivyDB{Binary: bin}).Verify(context.Background(), dir, &Meta{}); err == nil {
		t.Fatal("schema 1 accepted")
	}
	if err := (&TrivyDB{Binary: bin}).Verify(context.Background(), t.TempDir(), &Meta{}); err == nil {
		t.Fatal("empty dir accepted")
	}
}

func TestTrivyDBPinnedDigest(t *testing.T) {
	srv := fakeRegistry(t, map[string]string{"aquasec/trivy-db": testDigest})
	host := strings.TrimPrefix(srv.URL, "http://")
	src := &TrivyDB{Resolver: &OCIResolver{Scheme: "http"}, Repositories: []string{host + "/aquasec/trivy-db:2"}}
	r, err := src.Resolve(context.Background(), core.ContentPin{Version: testDigest})
	if err != nil || r.Ref != host+"/aquasec/trivy-db@"+testDigest {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := src.Resolve(context.Background(), core.ContentPin{Version: "sha256:" + strings.Repeat("0", 64)}); err == nil {
		t.Fatal("unknown pinned digest accepted")
	}
	if _, err := src.Resolve(context.Background(), core.ContentPin{Version: "latest"}); err == nil {
		t.Fatal("non-digest pin accepted")
	}
}

func TestTrivyJavaDBManaged(t *testing.T) {
	bin, log := fakeTrivy(t, "2026-10-02T01:05:41Z")
	src := &TrivyDB{Binary: bin, JavaDB: true, Repositories: []string{"127.0.0.1:1/aquasec/trivy-db:2"}, Resolver: &OCIResolver{Scheme: "http"}}
	m := newTestManager(t, src)
	if res := m.Refresh(context.Background(), []string{core.ContentTrivyJavaDB}, false); res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "--download-java-db-only") {
		t.Fatal("java db not downloaded")
	}
	rep := m.Report("trivy")
	if len(rep) != 2 || rep[1].Name != core.ContentTrivyJavaDB || rep[1].Version != "2026-09-30T00:00:00Z" {
		t.Fatalf("report %+v", rep)
	}
}

func TestTrivyBakedImport(t *testing.T) {
	baked := t.TempDir()
	_ = os.MkdirAll(filepath.Join(baked, "db"), 0o755)
	_ = os.WriteFile(filepath.Join(baked, "db", "metadata.json"), []byte(`{"Version":2,"UpdatedAt":"2026-09-01T00:00:00Z"}`), 0o644)
	m := newTestManager(t, &TrivyDB{BakedDir: baked})
	rep := m.Report("trivy")
	if len(rep) != 1 || rep[0].Source != "image" || rep[0].Version != "2026-09-01T00:00:00Z" {
		t.Fatalf("report %+v", rep)
	}
}
