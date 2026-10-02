package content

// On-disk layout of one kind of content:
//
//	<root>/<name>/versions/<id>/          the content (what the tool reads)
//	<root>/<name>/versions/<id>.meta.json what it is (Meta)
//	<root>/<name>/current -> versions/<id> the version scans use
//	<root>/<name>/.staging-*              a download in progress
//
// The metadata lives next to the version directory, not in it: a tool that
// loads a whole directory (semgrep --config <dir>) must see only content.
// "current" is swapped with rename(2) over a temporary symlink, so a reader
// sees the old or the new version, never neither.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	versionsDir   = "versions"
	currentLink   = "current"
	stagingPrefix = ".staging-"
	metaSuffix    = ".meta.json"
)

// Meta describes one installed version.
type Meta struct {
	// ID is the version directory's name.
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   string     `json:"version,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	FetchedAt time.Time  `json:"fetched_at"`
	// CheckedAt is when the source last confirmed this is the newest (or
	// the pinned) version: set on install and on every unchanged check.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Pinned is set when the policy pinned this version: it may be older
	// than what was installed before, so it is no floor for anti-rollback.
	Pinned bool   `json:"pinned,omitempty"`
	Source string `json:"source,omitempty"`
	Digest string `json:"digest,omitempty"`
	// Checks lists the verification steps this version passed.
	Checks []string `json:"checks,omitempty"`
	// Also is content installed together with this one in the same
	// directory (trivy's Java DB next to its vulnerability DB).
	Also []Meta `json:"also,omitempty"`
}

// store is the on-disk state of one content name.
type store struct {
	dir string // <root>/<name>
}

func (s store) versionsPath() string { return filepath.Join(s.dir, versionsDir) }
func (s store) versionPath(id string) string {
	return filepath.Join(s.dir, versionsDir, id)
}
func (s store) metaPath(id string) string {
	return filepath.Join(s.dir, versionsDir, id+metaSuffix)
}

func (s store) init() error {
	return os.MkdirAll(s.versionsPath(), 0o755)
}

// newStaging creates an empty staging directory for a download.
func (s store) newStaging() (string, error) {
	if err := s.init(); err != nil {
		return "", err
	}
	return os.MkdirTemp(s.dir, stagingPrefix)
}

// cleanStaging removes staging directories a crash left behind.
func (s store) cleanStaging() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			_ = os.RemoveAll(filepath.Join(s.dir, e.Name()))
		}
	}
}

// newVersionID names a new version directory: sortable by time, unique.
func newVersionID(now time.Time) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b[:])
}

// install moves a verified staging directory in as a new version and writes
// its metadata. It does not make it current.
func (s store) install(staging string, m *Meta) error {
	if err := s.init(); err != nil {
		return err
	}
	if err := writeJSON(s.metaPath(m.ID), m, 0o644); err != nil {
		return err
	}
	if err := os.Rename(staging, s.versionPath(m.ID)); err != nil {
		_ = os.Remove(s.metaPath(m.ID))
		return fmt.Errorf("install %s: %w", m.ID, err)
	}
	return nil
}

// installLink installs an external directory (content baked into the image)
// as a version, by symlink: removing the version removes only the link.
func (s store) installLink(target string, m *Meta) error {
	if err := s.init(); err != nil {
		return err
	}
	if err := writeJSON(s.metaPath(m.ID), m, 0o644); err != nil {
		return err
	}
	if err := os.Symlink(target, s.versionPath(m.ID)); err != nil {
		_ = os.Remove(s.metaPath(m.ID))
		return err
	}
	return nil
}

// markChecked records that the source confirmed version id is current.
func (s store) markChecked(id string, at time.Time) error {
	m, err := s.readMeta(id)
	if err != nil {
		return err
	}
	t := at.UTC()
	m.CheckedAt = &t
	return writeJSON(s.metaPath(id), m, 0o644)
}

// setCurrent points "current" at version id, atomically.
func (s store) setCurrent(id string) error {
	tmp := filepath.Join(s.dir, ".current-"+id)
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join(versionsDir, id), tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, currentLink)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// currentID returns the id "current" points at ("" when there is none).
func (s store) currentID() string {
	target, err := os.Readlink(filepath.Join(s.dir, currentLink))
	if err != nil {
		return ""
	}
	id := filepath.Base(target)
	if _, err := os.Stat(s.versionPath(id)); err != nil {
		return ""
	}
	return id
}

// readMeta reads a version's metadata.
func (s store) readMeta(id string) (*Meta, error) {
	raw, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m.ID = id
	return &m, nil
}

// versions lists the installed version ids, newest first.
func (s store) versions() []string {
	entries, err := os.ReadDir(s.versionsPath())
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), metaSuffix); ok {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids
}

// gc removes versions other than current, the newest keepPrevious others,
// and those inUse reports as held by a running scan.
func (s store) gc(keepPrevious int, inUse func(id string) bool) []string {
	cur := s.currentID()
	kept := 0
	var removed []string
	for _, id := range s.versions() {
		if id == cur || inUse(id) {
			continue
		}
		if kept < keepPrevious {
			kept++
			continue
		}
		// os.RemoveAll on a symlinked (image) version removes the link only.
		if err := os.RemoveAll(s.versionPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}
		_ = os.Remove(s.metaPath(id))
		removed = append(removed, id)
	}
	return removed
}

func writeJSON(path string, v any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
