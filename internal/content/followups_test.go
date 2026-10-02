package content

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Old content whose source has nothing newer is not stale: every check that
// confirms it is current records checked_at, and staleness uses it.
func TestCheckedAtConfirmsOldContentCurrent(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	clock := now
	src := newFake()
	src.set("v10.4.9", "sha256:9", now.Add(-15*24*time.Hour)) // newest release, 15 days old
	m, err := New(Config{Root: t.TempDir(), Logf: t.Logf, Now: func() time.Time { return clock }}, src)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.SetPolicy(core.ContentPolicy{Content: map[string]core.ContentPin{src.name: {MaxAgeHours: 7 * 24}}})
	m.Refresh(context.Background(), nil, false)
	rep := m.Report("nuclei")[0]
	if rep.CheckedAt == nil || !rep.CheckedAt.Equal(now) {
		t.Fatalf("checked_at on install: %+v", rep.CheckedAt)
	}
	if m.needsAttention() || rep.Stale(clock, 7*24*time.Hour) {
		t.Fatal("newest-but-old content is stale right after a check")
	}

	// Eight days later, not checked since: stale.
	clock = now.Add(8 * 24 * time.Hour)
	if !m.needsAttention() {
		t.Fatal("unconfirmed old content is not stale")
	}
	// A check that finds nothing newer confirms it again (persisted).
	if res := m.Refresh(context.Background(), nil, false); !res[0].Unchanged {
		t.Fatalf("%+v", res)
	}
	if m.needsAttention() {
		t.Fatal("still stale after an unchanged check")
	}
	meta, err := m.store(src.name).readMeta(m.store(src.name).currentID())
	if err != nil || meta.CheckedAt == nil || !meta.CheckedAt.Equal(clock) {
		t.Fatalf("checked_at not persisted: %+v %v", meta, err)
	}
	raw, _ := json.Marshal(m.Report("nuclei")[0])
	if !strings.Contains(string(raw), `"checked_at":"2026-10-10T00:00:00Z"`) {
		t.Fatalf("report %s", raw)
	}
}

// A pin added, changed or removed moves the content, and a pinned (older or
// oddly dated) version is no anti-rollback floor once the pin is removed.
func TestPinChangesMoveContent(t *testing.T) {
	src := newFake()
	src.set("v2", "sha256:2", time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	m := newTestManager(t, src)
	m.Refresh(context.Background(), nil, false)

	// Pin an older release whose recorded date is later than the latest's.
	src.set("v1", "sha256:1", time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC))
	_ = m.SetPolicy(core.ContentPolicy{Content: map[string]core.ContentPin{src.name: {Version: "v1"}}})
	if res := m.Refresh(context.Background(), nil, false); !res[0].Refreshed {
		t.Fatalf("pin added: %+v", res)
	}
	if v := m.Report("nuclei")[0].Version; v != "v1" {
		t.Fatalf("pinned version %s", v)
	}

	// Pin removed: back to the latest, although it is dated earlier.
	src.set("v2", "sha256:2", time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	_ = m.SetPolicy(core.ContentPolicy{})
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil || !res[0].Refreshed {
		t.Fatalf("pin removed: %+v", res)
	}
	if v := m.Report("nuclei")[0].Version; v != "v2" {
		t.Fatalf("after unpin %s", v)
	}
}

func TestRefreshCommandEveryContentInOneBucket(t *testing.T) {
	nucleiSrc := newFake()
	semgrepSrc := &SemgrepRules{Fetcher: &Fetcher{}} // unmanaged
	m := newTestManager(t, nucleiSrc, semgrepSrc)
	e := &CommandExecutor{Manager: m}
	res, err := e.Execute(context.Background(), &core.Command{Type: core.CommandTypeRefreshContent, Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	md := res.Metadata
	skipped := md["skipped"].(map[string]string)
	if !strings.Contains(skipped[core.ContentSemgrepRules], "no semgrep rulesets") {
		t.Fatalf("skipped %v", skipped)
	}
	count := map[string]int{}
	for _, n := range md["refreshed"].([]string) {
		count[n]++
	}
	for _, n := range md["unchanged"].([]string) {
		count[n]++
	}
	for n := range skipped {
		count[n]++
	}
	for n := range md["failed"].(map[string]string) {
		count[n]++
	}
	for _, n := range m.Names() {
		if count[n] != 1 {
			t.Errorf("%s in %d buckets: %v", n, count[n], md)
		}
	}
}

func TestNucleiPinnedReleaseDates(t *testing.T) {
	a := templateArchive(t, "v10.4.8", 6)
	mirror := &templateMirror{archives: map[string][]byte{}, sums: map[string]string{}, latest: "v10.4.9"}
	mirror.add(t, "v10.4.8", 6)
	mirror.archives["v10.4.8"] = a
	srv := mirror.serve(t)
	tags := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tags/v10.4.8" {
			_, _ = fmt.Fprint(w, `{"tag_name":"v10.4.8","published_at":"2026-09-09T10:00:00Z"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tags.Close()
	pin := core.ContentPin{Version: "v10.4.8"}

	// Default source: the release's own publication date.
	src := newMirrorSource(t, srv)
	src.TagURL = tags.URL + "/tags/{version}"
	r, err := src.Resolve(context.Background(), pin)
	if err != nil || r.UpdatedAt == nil || !r.UpdatedAt.Equal(time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("pinned release date %+v %v", r, err)
	}

	// An https mirror without a release API: undated (age from fetched_at),
	// never the fetch time.
	src.TagURL = ""
	dir := t.TempDir()
	r, err = src.Resolve(context.Background(), pin)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := src.Fetch(context.Background(), dir, r, pin)
	if err != nil || meta.UpdatedAt != nil {
		t.Fatalf("mirror archive dated %v %v", meta.UpdatedAt, err)
	}

	// A local file: dated by the file.
	local := t.TempDir()
	archive := filepath.Join(local, "nuclei-templates-v10.4.8.tar.gz")
	_ = os.WriteFile(archive, a, 0o644)
	mtime := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(archive, mtime, mtime)
	lsrc := &NucleiTemplates{ArchiveURL: "file://" + local + "/nuclei-templates-{version}.tar.gz", SHA256: mirror.sums["v10.4.8"], Fetcher: &Fetcher{}}
	r, err = lsrc.Resolve(context.Background(), pin)
	if err != nil {
		t.Fatal(err)
	}
	meta, err = lsrc.Fetch(context.Background(), t.TempDir(), r, pin)
	if err != nil || meta.UpdatedAt == nil || !meta.UpdatedAt.Equal(mtime) {
		t.Fatalf("local archive dated %v %v", meta.UpdatedAt, err)
	}
}

func TestWrapParserStamps(t *testing.T) {
	m := installFake(t, core.ContentNucleiTemplates, "nuclei", "v10.4.9")
	h := m.AcquireFor("nuclei", core.ContentNucleiTemplates)
	h.Release()
	p := m.WrapParser(fixedParser{tool: "nuclei"})
	if p.Name() != "fixed" {
		t.Fatal("name changed")
	}
	r, err := p.Parse(context.Background(), nil, &core.ParseOptions{ToolName: "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r.Tool)
	if !strings.Contains(string(raw), `"properties":{"content":[{"name":"nuclei-templates","version":"v10.4.9"`) {
		t.Fatalf("tool %s", raw)
	}
	var nilM *Manager
	if nilM.WrapParser(fixedParser{}) != core.Parser(fixedParser{}) {
		t.Fatal("nil manager wrapped the parser")
	}
}

type fixedParser struct{ tool string }

func (fixedParser) Name() string               { return "fixed" }
func (fixedParser) SupportedFormats() []string { return []string{"json"} }
func (fixedParser) CanParse([]byte) bool       { return true }
func (f fixedParser) Parse(context.Context, []byte, *core.ParseOptions) (*ctis.Report, error) {
	return &ctis.Report{Tool: &ctis.Tool{Name: f.tool}}, nil
}

// A version an older sensor installed under a pin, dated at its fetch time
// and without the pinned flag, does not block the move back to the latest.
func TestLegacyFetchDatedVersionIsNoRollbackFloor(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)
	src.set("v10.4.8", "sha256:8", time.Now().UTC())
	m.Refresh(context.Background(), nil, false)
	st := m.store(src.name)
	meta, _ := st.readMeta(st.currentID())
	meta.Pinned = false
	up := meta.FetchedAt
	meta.UpdatedAt = &up // dated at fetch, as the first release did
	if err := writeJSON(st.metaPath(meta.ID), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	src.set("v10.4.9", "sha256:9", time.Date(2026, 9, 16, 14, 58, 45, 0, time.UTC))
	if res := m.Refresh(context.Background(), nil, false); res[0].Err != nil || !res[0].Refreshed {
		t.Fatalf("stuck on the fetch-dated version: %+v", res)
	}
}
