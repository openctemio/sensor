package content

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

// Default nuclei-templates locations (GitHub releases).
const (
	DefaultNucleiLatestURL    = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
	DefaultNucleiTagURL       = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/tags/{version}"
	DefaultNucleiArchiveURL   = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{version}.tar.gz"
	DefaultNucleiChecksumsURL = "https://github.com/projectdiscovery/nuclei-templates/releases/download/{version}/nuclei-templates-{bare_version}_checksums.txt"
	// DefaultNucleiMinTemplates: a release has over ten thousand; fewer than
	// this means a broken or truncated archive.
	DefaultNucleiMinTemplates = 1000
	// DefaultNucleiMaxTemplateErrors is how many templates of a release
	// may fail nuclei's own validation before the release is refused. A
	// release is validated with the private configuration every scan uses
	// (nuclei.NewConfigHome), so a template fails only when this nuclei
	// cannot load it (a release newer than the engine, a broken template):
	// a few such templates do not hold back the rest of a release; more
	// mean the release and the engine do not match.
	DefaultNucleiMaxTemplateErrors = 10
	maxNucleiArchiveBytes          = 512 << 20
	// BakedReleaseFile records, next to nuclei's own config in the image
	// ($HOME/.config/nuclei), which release the baked templates are and
	// the digest of the archive they were extracted from (written at
	// image build after the archive's SHA-256 was verified).
	BakedReleaseFile = "openctem-templates-release.json"
)

var (
	nucleiTagRE = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.-]+)?$`)
	sha256HexRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// NucleiTemplates is the nuclei-templates release a sensor scans with.
type NucleiTemplates struct {
	Binary string // nuclei binary (default "nuclei"), for the load check
	// LatestURL answers the newest release: GitHub's releases/latest JSON
	// ({"tag_name", "published_at"}) or a plain-text tag. Empty: only a
	// pinned version (policy or Version) can be installed.
	LatestURL string
	// TagURL answers one release by tag ({version}), GitHub-shaped; it gives
	// a pinned release its publication date. Empty (mirrors): a pinned
	// release from a local file is dated by the file's mtime, one from an
	// https mirror has no publication date and its age is measured from
	// when the sensor installed it.
	TagURL string
	// ArchiveURL and ChecksumsURL locate a release; {version} is the tag
	// ("v10.4.9"), {bare_version} the tag without "v". https:// or a
	// local file (file:// or an absolute path).
	ArchiveURL   string
	ChecksumsURL string
	// LocalDir, when set, is a template directory installed as is (an
	// air-gapped host's copy), versioned by Version or its digest.
	LocalDir string
	// Version pins the release when the policy does not.
	Version string
	// SHA256 pins the archive digest (hex), instead of the checksums file.
	SHA256       string
	MinTemplates int
	// MaxTemplateErrors is how many templates may fail validation (0:
	// DefaultNucleiMaxTemplateErrors; negative: none).
	MaxTemplateErrors int
	BakedDir          string // templates baked into the image, imported first
	Fetcher           *Fetcher
	Timeout           time.Duration
}

// Name implements Source.
func (n *NucleiTemplates) Name() string { return core.ContentNucleiTemplates }

// Tool implements Source.
func (n *NucleiTemplates) Tool() string { return "nuclei" }

// Managed implements Source.
func (n *NucleiTemplates) Managed(core.ContentPin) bool { return true }

func (n *NucleiTemplates) binary() string { return firstNonEmpty(n.Binary, "nuclei") }

func (n *NucleiTemplates) minTemplates() int {
	if n.MinTemplates > 0 {
		return n.MinTemplates
	}
	return DefaultNucleiMinTemplates
}

func (n *NucleiTemplates) maxTemplateErrors() int {
	switch {
	case n.MaxTemplateErrors > 0:
		return n.MaxTemplateErrors
	case n.MaxTemplateErrors < 0:
		return 0
	}
	return DefaultNucleiMaxTemplateErrors
}

func expandVersion(tmpl, tag string) string {
	tmpl = strings.ReplaceAll(tmpl, "{bare_version}", strings.TrimPrefix(tag, "v"))
	return strings.ReplaceAll(tmpl, "{version}", tag)
}

// Resolve implements Source: the release tag (pinned or newest) and the
// archive digest from the release's checksums file (or the pinned digest).
func (n *NucleiTemplates) Resolve(ctx context.Context, pin core.ContentPin) (*Remote, error) {
	if n.LocalDir != "" {
		return &Remote{Version: firstNonEmpty(pin.Version, n.Version), Ref: n.LocalDir, Source: n.LocalDir}, nil
	}
	tag := firstNonEmpty(pin.Version, n.Version)
	var published *time.Time
	if tag != "" && n.TagURL != "" && nucleiTagRE.MatchString(tag) {
		// A pinned release: its own publication date, so a pin to an old
		// release shows its real age. A lookup failure is not fatal (the
		// checksum still verifies the archive).
		if _, pub, err := n.release(ctx, expandVersion(n.TagURL, tag)); err == nil {
			published = pub
		}
	}
	if tag == "" {
		if n.LatestURL == "" {
			return nil, errors.New("no release to install: set a version (policy or SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION) or a latest-release URL")
		}
		var err error
		tag, published, err = n.release(ctx, n.LatestURL)
		if err != nil {
			return nil, err
		}
	}
	if !nucleiTagRE.MatchString(tag) {
		return nil, fmt.Errorf("invalid nuclei-templates version %q", tag)
	}
	archive := expandVersion(n.ArchiveURL, tag)
	sum := strings.ToLower(n.SHA256)
	if sum == "" {
		var err error
		sum, err = n.checksum(ctx, tag)
		if err != nil {
			return nil, err
		}
	}
	if !sha256HexRE.MatchString(sum) {
		return nil, fmt.Errorf("invalid nuclei-templates sha256 %q", sum)
	}
	return &Remote{Version: tag, Digest: "sha256:" + sum, UpdatedAt: published, Ref: archive, Source: redactURL(archive)}, nil
}

// release reads a release document: GitHub's JSON ({"tag_name",
// "published_at"}) or a plain-text tag.
func (n *NucleiTemplates) release(ctx context.Context, u string) (string, *time.Time, error) {
	raw, err := n.Fetcher.get(ctx, u, 1<<20)
	if err != nil {
		return "", nil, fmt.Errorf("latest release: %w", err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rel struct {
			Tag       string    `json:"tag_name"`
			Published time.Time `json:"published_at"`
		}
		if err := json.Unmarshal(trimmed, &rel); err != nil {
			return "", nil, fmt.Errorf("latest release: %w", err)
		}
		var pub *time.Time
		if !rel.Published.IsZero() {
			p := rel.Published.UTC()
			pub = &p
		}
		return rel.Tag, pub, nil
	}
	return string(trimmed), nil, nil
}

// checksum reads the release checksums file and returns the .tar.gz digest.
func (n *NucleiTemplates) checksum(ctx context.Context, tag string) (string, error) {
	if n.ChecksumsURL == "" {
		return "", errors.New("no checksums file configured and no sha256 pinned: refusing unverifiable templates")
	}
	raw, err := n.Fetcher.get(ctx, expandVersion(n.ChecksumsURL, tag), 1<<20)
	if err != nil {
		return "", fmt.Errorf("checksums: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.HasSuffix(fields[1], ".tar.gz") {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", errors.New("checksums: no .tar.gz entry")
}

// Fetch implements Source.
func (n *NucleiTemplates) Fetch(ctx context.Context, dir string, r *Remote, _ core.ContentPin) (*Meta, error) {
	ctx, cancel := context.WithTimeout(ctx, firstDuration(n.Timeout, 15*time.Minute))
	defer cancel()
	if n.LocalDir != "" {
		if _, err := copyTree(n.LocalDir, dir); err != nil {
			return nil, err
		}
		dg, err := treeDigest(dir)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		return &Meta{Version: firstNonEmpty(r.Version, "local-"+dg[7:19]), Digest: dg, UpdatedAt: &now, Source: r.Source}, nil
	}
	archive := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+".tar.gz")
	defer func() { _ = os.Remove(archive) }()
	sum, err := n.Fetcher.download(ctx, r.Ref, archive, maxNucleiArchiveBytes)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if "sha256:"+sum != r.Digest {
		return nil, fmt.Errorf("archive sha256 %s does not match the published %s", sum, strings.TrimPrefix(r.Digest, "sha256:"))
	}
	if _, err := extractTarGz(archive, dir); err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}
	updated := r.UpdatedAt
	if updated == nil {
		// A local archive is dated by its file; an archive from an https
		// mirror without a publication date stays undated (its age is then
		// measured from FetchedAt).
		if p, ok := localPath(r.Ref); ok {
			if fi, err := os.Stat(p); err == nil {
				t := fi.ModTime().UTC()
				updated = &t
			}
		}
	}
	return &Meta{Version: r.Version, Digest: r.Digest, UpdatedAt: updated, Source: r.Source, Checks: []string{"sha256"}}, nil
}

// Verify implements Source: enough templates on disk, nuclei loads them,
// and nuclei's own validation (-validate, signed templates only) passes for
// all but at most maxTemplateErrors of them. Both run with the private
// configuration a scan of this version uses (templates directory, release,
// exclusion list), so what passes here is what a scan runs.
func (n *NucleiTemplates) Verify(ctx context.Context, dir string, m *Meta) error {
	count := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".yaml") {
			count++
		}
		return nil
	})
	min := n.minTemplates()
	if count < min {
		return fmt.Errorf("%d templates, expected at least %d", count, min)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	home, err := nuclei.NewConfigHome(dir, m.Version)
	if err != nil {
		return err
	}
	defer func() { _ = home.Close() }()
	out, err := run(ctx, n.binary(), []string{"-duc", "-t", dir, "-tl", "-silent", "-no-color"}, nil, home.Env())
	if err != nil {
		return fmt.Errorf("nuclei cannot load the templates: %w", err)
	}
	loaded := 0
	for _, line := range strings.Split(string(out), "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "[") {
			loaded++
		}
	}
	if loaded < min {
		return fmt.Errorf("nuclei loads %d templates, expected at least %d", loaded, min)
	}
	m.Checks = append(m.Checks, fmt.Sprintf("templates-%d", count), "nuclei-load")

	_, stderr, code, err := runCapture(ctx, n.binary(),
		[]string{"-validate", "-duc", "-disable-unsigned-templates", "-t", dir, "-no-color"}, home.Env())
	if err != nil {
		return fmt.Errorf("nuclei -validate: %w", err)
	}
	failed := nuclei.ValidateErrors(stderr)
	if max := n.maxTemplateErrors(); len(failed) > max {
		return fmt.Errorf("%d templates fail nuclei's validation (at most %d allowed), e.g. %s",
			len(failed), max, strings.Join(firstN(failed, 3), ", "))
	}
	if code != 0 && len(failed) == 0 {
		return fmt.Errorf("nuclei -validate exited %d: %s", code, lastLines(string(stderr), 2))
	}
	if len(failed) > 0 {
		m.Checks = append(m.Checks, fmt.Sprintf("nuclei-validate-%d-errors", len(failed)))
	} else {
		m.Checks = append(m.Checks, "nuclei-validate")
	}
	return nil
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Baked implements Importer: the templates an image was built with
// ($HOME/nuclei-templates), with the release and archive digest the image
// build recorded (BakedReleaseFile), else the version nuclei recorded.
func (n *NucleiTemplates) Baked() (string, *Meta, bool) {
	if n.BakedDir == "" {
		return "", nil, false
	}
	fi, err := os.Stat(n.BakedDir)
	if err != nil || !fi.IsDir() {
		return "", nil, false
	}
	entries, err := os.ReadDir(n.BakedDir)
	if err != nil || len(entries) == 0 {
		return "", nil, false
	}
	version, digest := "image", ""
	// The release's own date when the image recorded it: the directory's
	// mtime is the image build time, which would make every release
	// published between the baked one and the build look like a rollback.
	mod := fi.ModTime().UTC()
	published := &mod
	if home, err := os.UserHomeDir(); err == nil {
		cfgDir := filepath.Join(home, ".config", "nuclei")
		if rel, ok := readBakedRelease(filepath.Join(cfgDir, BakedReleaseFile)); ok {
			version, digest = rel.Version, rel.Digest
			if rel.UpdatedAt != nil {
				t := rel.UpdatedAt.UTC()
				published = &t
			}
		} else if raw, err := os.ReadFile(filepath.Join(cfgDir, ".templates-config.json")); err == nil {
			var cfg struct {
				Version string `json:"nuclei-templates-version"`
			}
			if json.Unmarshal(raw, &cfg) == nil && cfg.Version != "" {
				version = cfg.Version
			}
		}
	}
	m := &Meta{Version: version, Digest: digest, UpdatedAt: published, Source: "image"}
	if digest != "" {
		m.Checks = []string{"sha256"}
	}
	return n.BakedDir, m, true
}

// bakedRelease is BakedReleaseFile.
type bakedRelease struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
	// UpdatedAt is the release's date (its files' commit time).
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// readBakedRelease reads the image's record of its baked release. A record
// whose version is not a release tag or whose digest is not a sha256 is
// ignored (ok false).
func readBakedRelease(path string) (bakedRelease, bool) {
	raw, err := os.ReadFile(path) //nolint:gosec // a fixed file in the sensor's own home
	if err != nil || len(raw) > 4096 {
		return bakedRelease{}, false
	}
	var rel bakedRelease
	if json.Unmarshal(raw, &rel) != nil || !nucleiTagRE.MatchString(rel.Version) {
		return bakedRelease{}, false
	}
	hexsum, ok := strings.CutPrefix(rel.Digest, "sha256:")
	if !ok || !sha256HexRE.MatchString(hexsum) {
		return bakedRelease{}, false
	}
	return rel, true
}
