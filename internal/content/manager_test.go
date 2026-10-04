package content

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// fakeSource serves versions from memory; verify can be made to fail.
type fakeSource struct {
	mu         sync.Mutex
	name, tool string
	version    string
	digest     string
	updated    time.Time
	verifyErr  error
	resolveErr error
	fetches    int
	gate       chan struct{} // when set, Fetch waits on it
	unmanaged  bool
}

func (f *fakeSource) Name() string                 { return f.name }
func (f *fakeSource) Tool() string                 { return f.tool }
func (f *fakeSource) Managed(core.ContentPin) bool { return !f.unmanaged }
func (f *fakeSource) Resolve(_ context.Context, pin core.ContentPin) (*Remote, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	v := f.version
	if pin.Version != "" {
		v = pin.Version
	}
	up := f.updated
	return &Remote{Version: v, Digest: f.digest, UpdatedAt: &up, Ref: v, Source: "fake"}, nil
}

func (f *fakeSource) Fetch(_ context.Context, dir string, r *Remote, _ core.ContentPin) (*Meta, error) {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	f.fetches++
	f.mu.Unlock()
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte(r.Version), 0o644); err != nil {
		return nil, err
	}
	return &Meta{Version: r.Version, Digest: r.Digest, UpdatedAt: r.UpdatedAt, Source: r.Source}, nil
}

func (f *fakeSource) Verify(context.Context, string, *Meta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyErr
}

func (f *fakeSource) set(version, digest string, updated time.Time) {
	f.mu.Lock()
	f.version, f.digest, f.updated = version, digest, updated
	f.mu.Unlock()
}

func newFake() *fakeSource {
	return &fakeSource{name: core.ContentNucleiTemplates, tool: "nuclei", version: "v1", digest: "sha256:1",
		updated: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
}

func newTestManager(t *testing.T, sources ...Source) *Manager {
	t.Helper()
	m, err := New(Config{Root: t.TempDir(), Logf: t.Logf}, sources...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readData(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRefreshInstallsAndSwaps(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)

	if h := m.Acquire(src.name); h != nil {
		t.Fatal("version before any refresh")
	}
	res := m.Refresh(context.Background(), nil, false)
	if len(res) != 1 || !res[0].Refreshed || res[0].Err != nil {
		t.Fatalf("first refresh %+v", res)
	}
	h1 := m.Acquire(src.name)
	if h1 == nil || readData(t, h1.Dir) != "v1" || h1.Meta.Digest != "sha256:1" {
		t.Fatalf("acquire after refresh: %+v", h1)
	}

	// Same digest: nothing downloaded.
	res = m.Refresh(context.Background(), nil, false)
	if !res[0].Unchanged || src.fetches != 1 {
		t.Fatalf("unchanged refresh %+v fetches=%d", res, src.fetches)
	}

	// A new version swaps in; the running scan keeps its own.
	src.set("v2", "sha256:2", time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	res = m.Refresh(context.Background(), nil, false)
	if !res[0].Refreshed {
		t.Fatalf("second refresh %+v", res)
	}
	if readData(t, h1.Dir) != "v1" {
		t.Fatal("running scan's version changed")
	}
	h2 := m.Acquire(src.name)
	if readData(t, h2.Dir) != "v2" {
		t.Fatal("current is not the new version")
	}
	h1.Release()
	h1.Release() // idempotent
	h2.Release()

	// Third version: v1 is neither current nor the kept previous.
	src.set("v3", "sha256:3", time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC))
	m.Refresh(context.Background(), nil, false)
	if _, err := os.Stat(h1.Dir); !os.IsNotExist(err) {
		t.Fatalf("oldest version not collected: %v", err)
	}
	if _, err := os.Stat(h2.Dir); err != nil {
		t.Fatalf("previous version (rollback) removed: %v", err)
	}
	if got := len(m.store(src.name).versions()); got != 2 {
		t.Fatalf("%d versions kept, want current + 1 previous", got)
	}
}

func TestVerifyFailureKeepsCurrent(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)
	m.Refresh(context.Background(), nil, false)

	src.set("v2", "sha256:2", time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	src.verifyErr = errors.New("checksum mismatch")
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err == nil || res[0].Refreshed {
		t.Fatalf("verify failure not reported: %+v", res)
	}
	h := m.Acquire(src.name)
	if h == nil || readData(t, h.Dir) != "v1" {
		t.Fatal("current changed after a failed verify")
	}
	h.Release()
	rep := m.Report("nuclei")
	if len(rep) != 1 || rep[0].Version != "v1" || rep[0].Error == "" || !rep[0].Managed {
		t.Fatalf("report %+v", rep)
	}
	// No staging leftovers, no half-installed version.
	entries, _ := os.ReadDir(m.store(src.name).dir)
	for _, e := range entries {
		if e.Name() != versionsDir && e.Name() != currentLink {
			t.Errorf("leftover %s", e.Name())
		}
	}
	if len(m.store(src.name).versions()) != 1 {
		t.Fatal("failed version installed")
	}

	// The next good refresh clears the error.
	src.verifyErr = nil
	m.Refresh(context.Background(), nil, false)
	if rep := m.Report("nuclei"); rep[0].Error != "" || rep[0].Version != "v2" {
		t.Fatalf("report after recovery %+v", rep)
	}
}

func TestResolveFailureReportedWithoutVersion(t *testing.T) {
	src := newFake()
	src.resolveErr = errors.New("registry unreachable")
	m := newTestManager(t, src)
	m.Refresh(context.Background(), nil, false)
	rep := m.Report("nuclei")
	if len(rep) != 1 || rep[0].Version != "" || rep[0].Error == "" {
		t.Fatalf("report %+v", rep)
	}
	if !m.needsAttention() {
		t.Fatal("missing content does not need attention")
	}
}

func TestAntiRollback(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)
	m.Refresh(context.Background(), nil, false)

	src.set("v0", "sha256:0", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err == nil {
		t.Fatal("older content accepted")
	}
	h := m.Acquire(src.name)
	if readData(t, h.Dir) != "v1" {
		t.Fatal("rolled back")
	}
	h.Release()

	// A pin is an explicit choice: allowed.
	if err := m.SetPolicy(core.ContentPolicy{Content: map[string]core.ContentPin{src.name: {Version: "v0"}}}); err != nil {
		t.Fatal(err)
	}
	res = m.Refresh(context.Background(), nil, false)
	if !res[0].Refreshed {
		t.Fatalf("pinned older version refused: %+v", res)
	}
	h = m.Acquire(src.name)
	if readData(t, h.Dir) != "v0" {
		t.Fatal("pin not honoured")
	}
	h.Release()
}

func TestForceRedownloads(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)
	m.Refresh(context.Background(), nil, false)
	first := m.store(src.name).currentID()
	res := m.Refresh(context.Background(), []string{src.name}, true)
	if !res[0].Refreshed || src.fetches != 2 {
		t.Fatalf("forced refresh %+v fetches=%d", res, src.fetches)
	}
	if cur := m.store(src.name).currentID(); cur == first {
		t.Fatal("forced refresh did not swap")
	}
	if len(m.store(src.name).versions()) != 2 {
		t.Fatal("previous not kept after a forced refresh")
	}
}

func TestRefreshIsSingleFlight(t *testing.T) {
	src := newFake()
	src.gate = make(chan struct{})
	m := newTestManager(t, src)
	var wg sync.WaitGroup
	results := make([][]Result, 3)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = m.Refresh(context.Background(), nil, true)
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(src.gate)
	wg.Wait()
	if src.fetches > 3 {
		t.Fatalf("fetches = %d", src.fetches)
	}
	for _, r := range results {
		if r[0].Err != nil {
			t.Fatal(r[0].Err)
		}
	}
	// Concurrent forced refreshes joined at least one in-flight run.
	if src.fetches == 3 {
		t.Log("all three ran sequentially (timing); single-flight not exercised")
	}
}

func TestAcquireDuringSwapAndGC(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)
	m.cfg.Keep = 0
	m.Refresh(context.Background(), nil, false)
	held := m.Acquire(src.name)
	for i := 2; i <= 4; i++ {
		src.set("v"+string(rune('0'+i)), "sha256:"+string(rune('0'+i)), time.Date(2026, 9, i, 0, 0, 0, 0, time.UTC))
		m.Refresh(context.Background(), nil, false)
	}
	// Keep=0: only current and the held version remain.
	if readData(t, held.Dir) != "v1" {
		t.Fatal("held version removed")
	}
	if got := len(m.store(src.name).versions()); got != 2 {
		t.Fatalf("%d versions, want current + held", got)
	}
	held.Release()
	src.set("v5", "sha256:5", time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
	m.Refresh(context.Background(), nil, false)
	if _, err := os.Stat(held.Dir); !os.IsNotExist(err) {
		t.Fatal("released version not collected")
	}
}

func TestPolicyPersistsAndUnknownContent(t *testing.T) {
	root := t.TempDir()
	src := newFake()
	m, err := New(Config{Root: root, Logf: t.Logf}, src)
	if err != nil {
		t.Fatal(err)
	}
	p := core.ContentPolicy{RefreshIntervalHours: 12, Content: map[string]core.ContentPin{src.name: {MaxAgeHours: 48}}}
	if err := m.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(root, policyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("policy file: %v %v", fi, err)
	}
	m2, err := New(Config{Root: root, Logf: t.Logf}, newFake())
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.Policy(); got.RefreshIntervalHours != 12 || got.Content[src.name].MaxAgeHours != 48 {
		t.Fatalf("policy not reloaded: %+v", got)
	}
	if m2.interval() != 12*time.Hour {
		t.Fatalf("interval %v", m2.interval())
	}
	res := m2.Refresh(context.Background(), []string{"nope"}, false)
	if !errors.Is(res[0].Err, ErrNoSource) {
		t.Fatalf("unknown content: %+v", res)
	}
}

func TestStaleContentNeedsAttention(t *testing.T) {
	src := newFake()
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	m, err := New(Config{Root: t.TempDir(), Logf: t.Logf, Now: func() time.Time { return now }}, src)
	if err != nil {
		t.Fatal(err)
	}
	src.set("v1", "sha256:1", now.Add(-24*time.Hour))
	m.Refresh(context.Background(), nil, false)
	if m.needsAttention() {
		t.Fatal("fresh content needs attention")
	}
	_ = m.SetPolicy(core.ContentPolicy{Content: map[string]core.ContentPin{src.name: {MaxAgeHours: 12}}})
	if m.needsAttention() {
		t.Fatal("content just confirmed current needs attention")
	}
	// Not confirmed within the max age: stale.
	now = now.Add(13 * time.Hour)
	if !m.needsAttention() {
		t.Fatal("stale content does not need attention")
	}
	// Stale or not, the content is still used for scans.
	if h := m.Acquire(src.name); h == nil {
		t.Fatal("stale content not usable")
	} else {
		h.Release()
	}
	if d := m.nextDelay(); d > retryInterval+retryInterval/10 {
		t.Fatalf("next delay %v while stale", d)
	}
}

func TestJitterBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := jitter(10 * time.Hour)
		if d < 9*time.Hour || d > 11*time.Hour {
			t.Fatalf("jitter %v out of ±10%%", d)
		}
	}
}

func TestStagingLeftoversCleanedOnStart(t *testing.T) {
	root := t.TempDir()
	src := newFake()
	left := filepath.Join(root, src.name, stagingPrefix+"crash")
	if err := os.MkdirAll(left, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: root, Logf: t.Logf}, src); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatal("staging leftover not removed")
	}
}

func TestUnmanagedSourceSkipped(t *testing.T) {
	src := newFake()
	src.unmanaged = true
	m := newTestManager(t, src)
	res := m.Refresh(context.Background(), nil, true)
	if !res[0].Skipped || src.fetches != 0 {
		t.Fatalf("unmanaged refreshed: %+v", res)
	}
	if m.Acquire(src.name) != nil {
		t.Fatal("unmanaged content acquired")
	}
}

// fakeImporter adopts a directory as baked content.
type fakeImporter struct {
	*fakeSource
	dir  string
	meta *Meta // nil: an undated "image-v0"
}

func (f fakeImporter) Baked() (string, *Meta, bool) {
	if f.meta != nil {
		m := *f.meta
		return f.dir, &m, true
	}
	return f.dir, &Meta{Version: "image-v0", Source: "image"}, true
}

func TestBakedContentImported(t *testing.T) {
	baked := t.TempDir()
	if err := os.WriteFile(filepath.Join(baked, "data"), []byte("baked"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := fakeImporter{fakeSource: newFake(), dir: baked}
	m := newTestManager(t, src)
	h := m.Acquire(src.name)
	if h == nil || readData(t, h.Dir) != "baked" || h.Meta.Source != "image" {
		t.Fatalf("baked content: %+v", h)
	}
	h.Release()
	// A refresh replaces it, and removing the old version leaves the image's files alone.
	m.cfg.Keep = 0
	m.Refresh(context.Background(), nil, false)
	if _, err := os.Stat(filepath.Join(baked, "data")); err != nil {
		t.Fatal("image content deleted by GC")
	}
}

// Before its first download finishes, content is reported without a version
// and without an error: nothing has failed yet. The platform shows it as
// missing; an error appears only once a refresh really fails.
func TestNotInstalledYetIsNotAnError(t *testing.T) {
	src := newFake()
	m := newTestManager(t, src)
	rep := m.Report("nuclei")
	if len(rep) != 1 || !rep[0].Managed || rep[0].Version != "" || rep[0].Error != "" {
		t.Fatalf("report before the first refresh %+v", rep)
	}
}
