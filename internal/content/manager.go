// Package content manages the data the sensor's scanners scan with, apart
// from their binaries: trivy's vulnerability database, the nuclei templates
// and the semgrep rules (api docs/rfcs/RFC-031-scanner-content-and-managed-sensor-updates.md).
//
// For each kind of content the manager refreshes on a schedule and on demand
// (the platform's refresh_content command), downloads into a staging
// directory, verifies, and only then swaps the new version in atomically.
// A failed download or verification leaves the current version in place and
// is reported. Scans take the current version when they start (Acquire) and
// keep it to the end, so a refresh never changes content under a running
// scan; the previous version is kept for rollback. What the sensor has is
// reported per tool on the heartbeat (core.ToolInfo.Content).
//
// Where content comes from (registries, mirrors, local directories) is the
// sensor host's configuration only. The platform's policy can pin versions,
// set the maximum age and choose semgrep rulesets, but never a source.
package content

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Remote is what a source offers right now.
type Remote struct {
	// Version and Digest identify it; Digest may be empty when the source
	// cannot tell before downloading.
	Version   string
	Digest    string
	UpdatedAt *time.Time
	// Ref is the source's own handle for Fetch (a repository@digest, a URL).
	Ref string
	// Source names where it comes from (reported).
	Source string
}

// Source is one kind of content.
type Source interface {
	// Name is the content name (core.ContentTrivyDB, ...).
	Name() string
	// Tool is the tool that uses it ("trivy", "nuclei", "semgrep").
	Tool() string
	// Managed reports whether the content is managed under pin. A source
	// that is not managed is reported as such and never refreshed.
	Managed(pin core.ContentPin) bool
	// Resolve finds the version to install under pin.
	Resolve(ctx context.Context, pin core.ContentPin) (*Remote, error)
	// Fetch downloads r into the empty directory dir.
	Fetch(ctx context.Context, dir string, r *Remote, pin core.ContentPin) (*Meta, error)
	// Verify checks a fetched directory before it can become current, and
	// records the checks passed on m.
	Verify(ctx context.Context, dir string, m *Meta) error
}

// Unmanaged is implemented by a source that reports something when it is
// not managed (semgrep's per-scan registry fetch).
type Unmanaged interface {
	UnmanagedInfo() core.ContentInfo
}

// Preparer is implemented by a source that adjusts a version directory
// after install (trivy's shared Java DB link).
type Preparer interface {
	Prepare(versionDir string) error
}

// Importer is implemented by a source that can adopt content baked into
// the image as its first version.
type Importer interface {
	// Baked returns the directory and metadata of baked content, or ok false.
	Baked() (dir string, m *Meta, ok bool)
}

// Config configures a Manager.
type Config struct {
	// Root is the content directory.
	Root string
	// Interval is the default refresh interval (the policy may override it).
	Interval time.Duration
	// Keep is how many previous versions are kept for rollback: 0 means
	// the default (1), a negative value none.
	Keep int
	// Verbose logs every refresh.
	Verbose bool
	// Now is the clock (tests).
	Now func() time.Time
	// Logf logs (default: fmt.Printf with a prefix).
	Logf func(format string, args ...any)
}

// Result is the outcome of refreshing one content.
type Result struct {
	Name      string
	Refreshed bool // a new version became current
	Unchanged bool // the source offers what is current
	Skipped   bool // not managed
	// Reason says why a content was skipped.
	Reason string
	Err    error
}

// Manager manages the content of every source.
type Manager struct {
	cfg     Config
	sources map[string]Source
	order   []string

	mu      sync.Mutex
	inUse   map[string]int // "<name>/<id>" -> running scans
	lastErr map[string]string
	flight  map[string]*flight
	policy  core.ContentPolicy
	used    map[string][]core.ContentInfo // tool -> content of its last scan
	wake    chan struct{}
}

type flight struct {
	done chan struct{}
	res  Result
}

// ErrNoSource is returned for a content name the manager does not know.
var ErrNoSource = errors.New("unknown content")

// policyFile is where the platform's policy is kept.
const policyFile = "policy.json"

// New returns a manager over sources. It creates the root, removes staging
// directories a crash left behind, loads the stored policy and imports
// content baked into the image where nothing is installed yet.
func New(cfg Config, sources ...Source) (*Manager, error) {
	if cfg.Root == "" {
		return nil, errors.New("content: no root directory")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	switch {
	case cfg.Keep == 0:
		cfg.Keep = defaultKeep
	case cfg.Keep < 0:
		cfg.Keep = 0
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(format string, args ...any) { fmt.Printf("[content] "+format+"\n", args...) }
	}
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return nil, fmt.Errorf("content: %w", err)
	}
	m := &Manager{
		cfg:     cfg,
		sources: map[string]Source{},
		inUse:   map[string]int{},
		lastErr: map[string]string{},
		flight:  map[string]*flight{},
		used:    map[string][]core.ContentInfo{},
		wake:    make(chan struct{}, 1),
	}
	for _, s := range sources {
		if s == nil {
			continue
		}
		m.sources[s.Name()] = s
		m.order = append(m.order, s.Name())
		st := m.store(s.Name())
		st.cleanStaging()
		m.importBaked(s)
	}
	m.loadPolicy()
	return m, nil
}

func (m *Manager) store(name string) store {
	return store{dir: filepath.Join(m.cfg.Root, name)}
}

// importBaked adopts content baked into the image as the first version.
func (m *Manager) importBaked(s Source) {
	imp, ok := s.(Importer)
	if !ok {
		return
	}
	st := m.store(s.Name())
	if st.currentID() != "" || len(st.versions()) > 0 {
		return
	}
	dir, meta, ok := imp.Baked()
	if !ok {
		return
	}
	meta.ID = newVersionID(m.cfg.Now())
	meta.Name = s.Name()
	if meta.FetchedAt.IsZero() {
		meta.FetchedAt = m.cfg.Now().UTC()
	}
	if err := st.installLink(dir, meta); err != nil {
		m.cfg.Logf("%s: could not import the image's content: %v", s.Name(), err)
		return
	}
	if err := st.setCurrent(meta.ID); err != nil {
		m.cfg.Logf("%s: could not import the image's content: %v", s.Name(), err)
		return
	}
	m.cfg.Logf("%s: using the content baked into the image (%s) until the first refresh", s.Name(), meta.Version)
}

// Names returns the content names, in registration order.
func (m *Manager) Names() []string { return append([]string(nil), m.order...) }

// Root returns the content directory.
func (m *Manager) Root() string { return m.cfg.Root }

// Handle is a version held by a running scan.
type Handle struct {
	// Dir is the version directory (absolute, resolved).
	Dir  string
	Meta Meta
	m    *Manager
	key  string
	once sync.Once
}

// Release lets the version be removed once it is neither current nor kept.
func (h *Handle) Release() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		h.m.mu.Lock()
		h.m.inUse[h.key]--
		if h.m.inUse[h.key] <= 0 {
			delete(h.m.inUse, h.key)
		}
		h.m.mu.Unlock()
	})
}

// Info is the handle's content as reported.
func (h *Handle) Info() core.ContentInfo { return infoOf(&h.Meta) }

// Acquire returns the current version of content name for a scan, or nil
// when there is none (the scan then runs as the tool would on its own).
// The caller must Release it when the scan ends.
func (m *Manager) Acquire(name string) *Handle {
	if m == nil {
		return nil
	}
	src, ok := m.sources[name]
	if !ok || !src.Managed(m.pin(name)) {
		return nil
	}
	st := m.store(name)
	// Hold the lock across the read so GC (which takes it) cannot remove
	// the version between reading "current" and counting the hold.
	m.mu.Lock()
	defer m.mu.Unlock()
	id := st.currentID()
	if id == "" {
		return nil
	}
	meta, err := st.readMeta(id)
	if err != nil {
		return nil
	}
	dir, err := filepath.EvalSymlinks(st.versionPath(id))
	if err != nil {
		return nil
	}
	key := name + "/" + id
	m.inUse[key]++
	return &Handle{Dir: dir, Meta: *meta, m: m, key: key}
}

// AcquireWait is Acquire for a lookup that must not conclude "not
// installed" from an install in progress: when content name has no current
// version yet but a refresh of it is running, it waits for that refresh
// (until ctx ends) and takes what it installed. A version that is already
// current is returned at once; a refresh replacing it never blocks a reader,
// which keeps the version it took (the swap is atomic). nil: nothing is
// installed and no refresh is running, the refresh failed, or ctx ended.
func (m *Manager) AcquireWait(ctx context.Context, name string) *Handle {
	if m == nil {
		return nil
	}
	if h := m.Acquire(name); h != nil {
		return h
	}
	m.mu.Lock()
	f := m.flight[canonicalName(name)]
	m.mu.Unlock()
	if f == nil {
		return nil
	}
	select {
	case <-f.done:
	case <-ctx.Done():
		return nil
	}
	return m.Acquire(name)
}

// NoteUsed records the content a scan of tool used, for its results.
func (m *Manager) NoteUsed(tool string, content []core.ContentInfo) {
	if m == nil || len(content) == 0 {
		return
	}
	m.mu.Lock()
	m.used[tool] = append([]core.ContentInfo(nil), content...)
	m.mu.Unlock()
}

// LastUsed returns the content the last scan of tool started with.
func (m *Manager) LastUsed(tool string) []core.ContentInfo {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.ContentInfo(nil), m.used[tool]...)
}

// Policy returns the policy in force.
func (m *Manager) Policy() core.ContentPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policy
}

// pin returns the policy for content name.
func (m *Manager) pin(name string) core.ContentPin {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policy.Content[name]
}

// SetPolicy replaces the policy and keeps it for the next start.
func (m *Manager) SetPolicy(p core.ContentPolicy) error {
	m.mu.Lock()
	m.policy = p
	m.mu.Unlock()
	if err := writeJSON(filepath.Join(m.cfg.Root, policyFile), p, 0o600); err != nil {
		return fmt.Errorf("content: save policy: %w", err)
	}
	m.Wake()
	return nil
}

func (m *Manager) loadPolicy() {
	raw, err := os.ReadFile(filepath.Join(m.cfg.Root, policyFile))
	if err != nil {
		return
	}
	req, err := core.ParseRefreshContentRequest([]byte(`{"policy":` + string(raw) + `}`))
	if err != nil || req.Policy == nil {
		m.cfg.Logf("ignoring the stored policy: %v", err)
		return
	}
	m.policy = *req.Policy
}

// Refresh refreshes the named content (all when names is empty). Content
// still within its maximum age is refreshed too: the source is asked what
// it has and nothing is downloaded when that is what is current, unless
// force is set. A refresh already running for a content is joined, not
// repeated.
func (m *Manager) Refresh(ctx context.Context, names []string, force bool) []Result {
	if len(names) == 0 {
		names = m.order
	}
	out := make([]Result, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		n = canonicalName(n)
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, m.refreshOne(ctx, n, force))
	}
	return out
}

// canonicalName maps content installed together with another to it.
func canonicalName(n string) string {
	if n == core.ContentTrivyJavaDB {
		return core.ContentTrivyDB
	}
	return n
}

func (m *Manager) refreshOne(ctx context.Context, name string, force bool) Result {
	if _, ok := m.sources[name]; !ok {
		return Result{Name: name, Err: fmt.Errorf("%w %q", ErrNoSource, name)}
	}
	m.mu.Lock()
	if f, ok := m.flight[name]; ok {
		m.mu.Unlock()
		select {
		case <-f.done:
			return f.res
		case <-ctx.Done():
			return Result{Name: name, Err: ctx.Err()}
		}
	}
	f := &flight{done: make(chan struct{})}
	m.flight[name] = f
	m.mu.Unlock()

	f.res = m.doRefresh(ctx, name, force)

	m.mu.Lock()
	delete(m.flight, name)
	if f.res.Err != nil {
		m.lastErr[name] = shortError(f.res.Err)
	} else {
		delete(m.lastErr, name)
	}
	m.mu.Unlock()
	close(f.done)
	return f.res
}

func (m *Manager) doRefresh(ctx context.Context, name string, force bool) Result {
	src := m.sources[name]
	pin := m.pin(name)
	res := Result{Name: name}
	if !src.Managed(pin) {
		res.Skipped = true
		res.Reason = "not managed on this sensor"
		if name == core.ContentSemgrepRules {
			res.Reason = "not managed: no semgrep rulesets chosen (semgrep fetches its rules per scan)"
		}
		return res
	}
	st := m.store(name)
	var cur *Meta
	if id := st.currentID(); id != "" {
		cur, _ = st.readMeta(id)
	}

	remote, err := src.Resolve(ctx, pin)
	if err != nil {
		res.Err = fmt.Errorf("resolve: %w", err)
		return res
	}
	if !force && cur != nil && remote.Digest != "" && remote.Digest == cur.Digest {
		res.Unchanged = true
		m.markChecked(name, cur.ID)
		return res
	}

	staging, err := st.newStaging()
	if err != nil {
		res.Err = err
		return res
	}
	defer func() { _ = os.RemoveAll(staging) }() // no-op after a successful install

	meta, err := src.Fetch(ctx, staging, remote, pin)
	if err != nil {
		res.Err = fmt.Errorf("fetch: %w", err)
		return res
	}
	if err := src.Verify(ctx, staging, meta); err != nil {
		res.Err = fmt.Errorf("verify: %w", err)
		return res
	}
	if !force && cur != nil && sameContent(meta, cur) {
		res.Unchanged = true
		m.markChecked(name, cur.ID)
		return res
	}
	// Anti-rollback: never replace content with older content unless the
	// policy pins exactly that version.
	// The installed content itself (a forced refresh of the same digest) is
	// no rollback, whatever dates the two copies carry.
	if cur != nil && !cur.Pinned && datedByPublisher(cur) && pin.Version == "" && meta.UpdatedAt != nil && cur.UpdatedAt != nil &&
		meta.UpdatedAt.Before(*cur.UpdatedAt) && !sameContent(meta, cur) {
		res.Err = fmt.Errorf("verify: the source offers %s, older than the installed %s (refusing a rollback; pin the version to install it)",
			meta.UpdatedAt.UTC().Format(time.RFC3339), cur.UpdatedAt.UTC().Format(time.RFC3339))
		return res
	}

	meta.Name = name
	meta.ID = newVersionID(m.cfg.Now())
	if meta.FetchedAt.IsZero() {
		meta.FetchedAt = m.cfg.Now().UTC()
	}
	checked := m.cfg.Now().UTC()
	meta.CheckedAt = &checked
	meta.Pinned = pin.Version != ""
	if err := st.install(staging, meta); err != nil {
		res.Err = err
		return res
	}
	if p, ok := src.(Preparer); ok {
		if err := p.Prepare(st.versionPath(meta.ID)); err != nil {
			m.cfg.Logf("%s: %v", name, err)
		}
	}
	m.mu.Lock()
	err = st.setCurrent(meta.ID)
	m.mu.Unlock()
	if err != nil {
		res.Err = fmt.Errorf("swap: %w", err)
		return res
	}
	res.Refreshed = true
	m.cfg.Logf("%s: now %s (%s)", name, meta.Version, firstNonEmpty(meta.Digest, meta.Source))
	m.gc(name)
	return res
}

// datedByPublisher reports whether a version's updated_at is a publication
// date. A version whose date is its own install time (one installed under a
// pin by an older sensor, dated at fetch) is no floor for anti-rollback.
func datedByPublisher(m *Meta) bool {
	if m.UpdatedAt == nil {
		return false
	}
	d := m.UpdatedAt.Sub(m.FetchedAt)
	return d < -time.Minute || d > time.Minute
}

// sameContent reports whether a fetched version is the installed one: the
// same digest, or, without digests, the same version.
func sameContent(a, b *Meta) bool {
	if a.Digest != "" || b.Digest != "" {
		return a.Digest == b.Digest
	}
	return a.Version != "" && a.Version == b.Version
}

// gc removes old versions of name no scan holds.
func (m *Manager) gc(name string) {
	st := m.store(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range st.gc(m.cfg.Keep, func(id string) bool { return m.inUse[name+"/"+id] > 0 }) {
		if m.cfg.Verbose {
			m.cfg.Logf("%s: removed old version %s", name, id)
		}
	}
}

// Report returns the content of tool as the heartbeat reports it.
func (m *Manager) Report(tool string) []core.ContentInfo {
	if m == nil {
		return nil
	}
	var out []core.ContentInfo
	for _, name := range m.order {
		src := m.sources[name]
		if src.Tool() != tool {
			continue
		}
		pin := m.pin(name)
		m.mu.Lock()
		lastErr := m.lastErr[name]
		m.mu.Unlock()
		if !src.Managed(pin) {
			if u, ok := src.(Unmanaged); ok {
				out = append(out, u.UnmanagedInfo())
			}
			continue
		}
		st := m.store(name)
		var meta *Meta
		if id := st.currentID(); id != "" {
			meta, _ = st.readMeta(id)
		}
		if meta == nil {
			// Nothing installed yet. An error is reported only once a refresh
			// really failed; a first download in progress is not a failure
			// (the platform shows the content as missing).
			out = append(out, core.ContentInfo{Name: name, Managed: true, Error: lastErr})
			continue
		}
		info := infoOf(meta)
		info.Error = lastErr
		out = append(out, info)
		for i := range meta.Also {
			also := infoOf(&meta.Also[i])
			also.Error = lastErr
			out = append(out, also)
		}
	}
	return out
}

// Content returns every content's report, for a command result.
func (m *Manager) Content() []core.ContentInfo {
	var out []core.ContentInfo
	seen := map[string]bool{}
	for _, name := range m.order {
		tool := m.sources[name].Tool()
		if seen[tool] {
			continue
		}
		seen[tool] = true
		out = append(out, m.Report(tool)...)
	}
	return out
}

func infoOf(meta *Meta) core.ContentInfo {
	fetched := meta.FetchedAt
	info := core.ContentInfo{
		Name: meta.Name, Version: meta.Version, UpdatedAt: meta.UpdatedAt,
		Source: meta.Source, Digest: meta.Digest, Managed: true,
	}
	if !fetched.IsZero() {
		info.FetchedAt = &fetched
	}
	info.CheckedAt = meta.CheckedAt
	return info
}

// markChecked records that the source confirmed the current version of name.
func (m *Manager) markChecked(name, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.store(name).markChecked(id, m.cfg.Now()); err != nil {
		m.cfg.Logf("%s: %v", name, err)
	}
}

// needsRefresh reports content that is missing, stale under the policy or
// whose last refresh failed.
func (m *Manager) needsAttention() bool {
	now := m.cfg.Now()
	for _, name := range m.order {
		src := m.sources[name]
		pin := m.pin(name)
		if !src.Managed(pin) {
			continue
		}
		m.mu.Lock()
		failed := m.lastErr[name] != ""
		m.mu.Unlock()
		if failed {
			return true
		}
		st := m.store(name)
		id := st.currentID()
		if id == "" {
			return true
		}
		meta, err := st.readMeta(id)
		if err != nil {
			return true
		}
		if max := pin.MaxAge(); max > 0 {
			// Old content whose source has nothing newer is not stale
			// (core.ContentInfo.Stale): only content not confirmed current
			// within the max age is.
			if infoOf(meta).Stale(now, max) {
				return true
			}
		}
	}
	return false
}

// Default schedule.
const (
	DefaultInterval = 6 * time.Hour
	// retryInterval bounds the wait while content is missing, stale or failing.
	retryInterval = time.Hour
	firstDelay    = 30 * time.Second
	refreshBudget = 30 * time.Minute
)

// interval is the refresh interval in force.
func (m *Manager) interval() time.Duration {
	if h := m.Policy().RefreshIntervalHours; h > 0 {
		return time.Duration(h) * time.Hour
	}
	return m.cfg.Interval
}

// nextDelay is the wait before the next scheduled refresh: the interval
// (shorter while something needs attention), with ±10% jitter so a fleet
// does not hit a registry at the same moment.
func (m *Manager) nextDelay() time.Duration {
	d := m.interval()
	if m.needsAttention() && d > retryInterval {
		d = retryInterval
	}
	return jitter(d)
}

func jitter(d time.Duration) time.Duration {
	span := int64(d) / 10
	if span <= 0 {
		return d
	}
	return d - time.Duration(span) + time.Duration(rand.Int64N(2*span+1)) //nolint:gosec // schedule jitter, not security
}

// Wake makes the scheduler re-plan now (a new policy).
func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Run refreshes on schedule until ctx ends: a first check shortly after
// start, then every interval.
func (m *Manager) Run(ctx context.Context) {
	timer := time.NewTimer(jitter(firstDelay))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(jitter(firstDelay))
			continue
		case <-timer.C:
		}
		rctx, cancel := context.WithTimeout(ctx, refreshBudget)
		for _, r := range m.Refresh(rctx, nil, false) {
			if r.Err != nil {
				m.cfg.Logf("%s: refresh failed, scanning with the installed version: %v", r.Name, r.Err)
			}
		}
		cancel()
		timer.Reset(m.nextDelay())
	}
}

func shortError(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
