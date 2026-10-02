package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

type tarEntry struct {
	name, body string
	typ        byte
	link       string
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func templateArchive(t *testing.T, tag string, n int) []byte {
	t.Helper()
	entries := []tarEntry{{name: "nuclei-templates-" + tag + "/", typ: tar.TypeDir}}
	for i := 0; i < n; i++ {
		entries = append(entries, tarEntry{
			name: fmt.Sprintf("nuclei-templates-%s/http/t%d.yaml", tag, i),
			body: fmt.Sprintf("id: t%d\n# digest: abc\n", i),
		})
	}
	return makeTarGz(t, entries)
}

// fakeNuclei lists every .yaml under -t for -tl.
func fakeNuclei(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "nuclei")
	script := `#!/bin/sh
dir=""
while [ $# -gt 0 ]; do
  [ "$1" = "-t" ] && dir="$2"
  shift
done
[ -n "$dir" ] || exit 2
find "$dir" -name '*.yaml' | sed 's|.*/||'
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	return bin
}

// templateMirror serves releases: /latest, /archive/<tag>.tar.gz and
// /checksums/<tag>.
type templateMirror struct {
	archives map[string][]byte
	sums     map[string]string
	latest   string
}

func (m *templateMirror) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/latest":
			_, _ = fmt.Fprintf(w, `{"tag_name":%q,"published_at":"2026-09-16T14:58:45Z"}`, m.latest)
		case strings.HasPrefix(r.URL.Path, "/archive/"):
			tag := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/archive/"), ".tar.gz")
			_, _ = w.Write(m.archives[tag])
		case strings.HasPrefix(r.URL.Path, "/checksums/"):
			tag := strings.TrimPrefix(r.URL.Path, "/checksums/")
			_, _ = fmt.Fprintf(w, "%s  nuclei-templates-%s.tar.gz\nffff  nuclei-templates-%s.zip\n", m.sums[tag], strings.TrimPrefix(tag, "v"), strings.TrimPrefix(tag, "v"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (m *templateMirror) add(t *testing.T, tag string, n int) {
	a := templateArchive(t, tag, n)
	sum := sha256.Sum256(a)
	m.archives[tag] = a
	m.sums[tag] = hex.EncodeToString(sum[:])
}

func newMirrorSource(t *testing.T, srv *httptest.Server) *NucleiTemplates {
	return &NucleiTemplates{
		Binary: fakeNuclei(t), LatestURL: srv.URL + "/latest",
		ArchiveURL: srv.URL + "/archive/{version}.tar.gz", ChecksumsURL: srv.URL + "/checksums/{version}",
		MinTemplates: 5, Fetcher: &Fetcher{AllowHTTP: true},
	}
}

func TestNucleiTemplatesFromMirror(t *testing.T) {
	mirror := &templateMirror{archives: map[string][]byte{}, sums: map[string]string{}, latest: "v10.4.9"}
	mirror.add(t, "v10.4.9", 8)
	srv := mirror.serve(t)
	m := newTestManager(t, newMirrorSource(t, srv))

	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil || !res[0].Refreshed {
		t.Fatalf("refresh %+v", res)
	}
	h := m.Acquire(core.ContentNucleiTemplates)
	defer h.Release()
	if h.Meta.Version != "v10.4.9" || h.Meta.Digest != "sha256:"+mirror.sums["v10.4.9"] || h.Meta.UpdatedAt == nil {
		t.Fatalf("meta %+v", h.Meta)
	}
	// The archive's top directory is stripped.
	if _, err := os.Stat(filepath.Join(h.Dir, "http", "t0.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestNucleiChecksumMismatchKeepsOld(t *testing.T) {
	mirror := &templateMirror{archives: map[string][]byte{}, sums: map[string]string{}, latest: "v10.4.8"}
	mirror.add(t, "v10.4.8", 6)
	srv := mirror.serve(t)
	m := newTestManager(t, newMirrorSource(t, srv))
	m.Refresh(context.Background(), nil, false)

	// A tampered archive: the published checksum no longer matches.
	mirror.add(t, "v10.4.9", 6)
	mirror.archives["v10.4.9"] = templateArchive(t, "v10.4.9", 7)
	mirror.latest = "v10.4.9"
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "does not match") {
		t.Fatalf("tampered archive: %+v", res)
	}
	if rep := m.Report("nuclei"); rep[0].Version != "v10.4.8" || rep[0].Error == "" {
		t.Fatalf("report %+v", rep)
	}
}

func TestNucleiTooFewTemplatesRejected(t *testing.T) {
	mirror := &templateMirror{archives: map[string][]byte{}, sums: map[string]string{}, latest: "v1.0.0"}
	mirror.add(t, "v1.0.0", 2)
	srv := mirror.serve(t)
	m := newTestManager(t, newMirrorSource(t, srv))
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil {
		t.Fatal("truncated release accepted")
	}
}

func TestNucleiPinnedVersionAndLocalFiles(t *testing.T) {
	// Air-gapped: archive and checksums are local files, the version pinned.
	dir := t.TempDir()
	a := templateArchive(t, "v10.4.7", 6)
	sum := sha256.Sum256(a)
	_ = os.WriteFile(filepath.Join(dir, "nuclei-templates-v10.4.7.tar.gz"), a, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "sums-v10.4.7.txt"), []byte(hex.EncodeToString(sum[:])+"  nuclei-templates-10.4.7.tar.gz\n"), 0o644)
	src := &NucleiTemplates{
		Binary: fakeNuclei(t), ArchiveURL: "file://" + dir + "/nuclei-templates-{version}.tar.gz",
		ChecksumsURL: dir + "/sums-{version}.txt", MinTemplates: 5, Fetcher: &Fetcher{},
	}
	m := newTestManager(t, src)
	// No latest URL and no pin: nothing to install.
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil {
		t.Fatal("installed without a version")
	}
	_ = m.SetPolicy(core.ContentPolicy{Content: map[string]core.ContentPin{core.ContentNucleiTemplates: {Version: "v10.4.7"}}})
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	if rep := m.Report("nuclei"); rep[0].Version != "v10.4.7" {
		t.Fatalf("report %+v", rep)
	}
}

func TestNucleiLocalDirectory(t *testing.T) {
	local := t.TempDir()
	for i := 0; i < 6; i++ {
		_ = os.MkdirAll(filepath.Join(local, "http"), 0o755)
		_ = os.WriteFile(filepath.Join(local, "http", fmt.Sprintf("t%d.yaml", i)), []byte("id: x"), 0o644)
	}
	src := &NucleiTemplates{Binary: fakeNuclei(t), LocalDir: local, MinTemplates: 5, Fetcher: &Fetcher{}}
	m := newTestManager(t, src)
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	// Same files again: unchanged.
	if res = m.Refresh(context.Background(), nil, false); !res[0].Unchanged {
		t.Fatalf("%+v", res)
	}
}

func TestFetcherRefusesPlainHTTP(t *testing.T) {
	if _, err := (&Fetcher{}).get(context.Background(), "http://example.com/x", 10); err == nil {
		t.Fatal("http:// accepted")
	}
}

func TestExtractRejectsUnsafeArchives(t *testing.T) {
	cases := map[string][]tarEntry{
		"traversal": {{name: "top/../../etc/passwd", body: "x"}},
		"absolute":  {{name: "/etc/passwd", body: "x"}},
		"symlink":   {{name: "top/link", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		"hardlink":  {{name: "top/link", typ: tar.TypeLink, link: "top/a"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.tar.gz")
			_ = os.WriteFile(path, makeTarGz(t, entries), 0o600)
			out := t.TempDir()
			if _, err := extractTarGz(path, out); err == nil {
				t.Fatal("unsafe archive extracted")
			}
		})
	}
}

func TestCopyTreeRefusesSymlinks(t *testing.T) {
	src := t.TempDir()
	_ = os.Symlink("/etc/passwd", filepath.Join(src, "p"))
	if _, err := copyTree(src, t.TempDir()); err == nil {
		t.Fatal("symlink copied")
	}
}
