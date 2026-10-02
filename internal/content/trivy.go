package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// DefaultTrivyDBRepositories are tried in order: trivy's own default
// (mirror.gcr.io) and the upstream registry.
var DefaultTrivyDBRepositories = []string{"mirror.gcr.io/aquasec/trivy-db:2", "ghcr.io/aquasecurity/trivy-db:2"}

// trivyDBSchema is the database schema version trivy (0.69 through 0.75) reads.
const trivyDBSchema = 2

// sharedJavaDB is where trivy keeps a Java DB it downloads by itself when the
// sensor does not manage it, shared by every vulnerability-DB version.
const sharedJavaDB = "shared-java-db"

// TrivyDB is trivy's vulnerability database (and, optionally, its Java DB):
// one version directory is a trivy cache directory (db/, java-db/) that
// scans use with --cache-dir and --skip-db-update.
type TrivyDB struct {
	Binary       string   // trivy binary (default "trivy")
	Repositories []string // OCI repositories, tried in order
	// JavaDB also manages the Java DB (about 800 MB more per version).
	JavaDB bool
	// JavaRepository overrides trivy's Java DB repository.
	JavaRepository string
	Resolver       *OCIResolver
	// BakedDir is a trivy cache directory with a DB baked into the image
	// (TRIVY_CACHE_DIR), imported as the first version.
	BakedDir string
	// Root is the manager's content root (for the shared Java DB link).
	Root    string
	Timeout time.Duration
}

// Name implements Source.
func (t *TrivyDB) Name() string { return core.ContentTrivyDB }

// Tool implements Source.
func (t *TrivyDB) Tool() string { return "trivy" }

// Managed implements Source: always, when configured.
func (t *TrivyDB) Managed(core.ContentPin) bool { return true }

func (t *TrivyDB) binary() string { return firstNonEmpty(t.Binary, "trivy") }

func (t *TrivyDB) repositories() []string {
	if len(t.Repositories) > 0 {
		return t.Repositories
	}
	return DefaultTrivyDBRepositories
}

// Resolve implements Source: the first repository that answers gives the
// digest (the pinned one when the policy pins it). If none answers, the
// first repository's tag is used without a digest: trivy still verifies
// what it downloads, and the version is compared after the download.
func (t *TrivyDB) Resolve(ctx context.Context, pin core.ContentPin) (*Remote, error) {
	if pin.Version != "" && !digestRE.MatchString(pin.Version) {
		return nil, fmt.Errorf("pinned trivy-db version %q is not a sha256 digest", pin.Version)
	}
	resolver := t.Resolver
	if resolver == nil {
		resolver = &OCIResolver{}
	}
	var errs []string
	for _, repo := range t.repositories() {
		ref, err := ParseOCIRef(repo)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if pin.Version != "" {
			ref.Tag, ref.Digest = "", pin.Version
			// Check the pinned digest exists here before choosing this repository.
			if _, err := resolver.ResolveDigest(ctx, OCIRef{Host: ref.Host, Repo: ref.Repo, Tag: pin.Version}); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			return &Remote{Digest: pin.Version, Ref: ref.String(), Source: ref.Name()}, nil
		}
		dg, err := resolver.ResolveDigest(ctx, ref)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		pinned := OCIRef{Host: ref.Host, Repo: ref.Repo, Digest: dg}
		return &Remote{Digest: dg, Ref: pinned.String(), Source: ref.String()}, nil
	}
	if pin.Version != "" {
		return nil, fmt.Errorf("pinned digest %s not found: %s", pin.Version, strings.Join(errs, "; "))
	}
	// Fall back: let trivy try every repository by tag.
	return &Remote{Ref: strings.Join(t.repositories(), ","), Source: t.repositories()[0]}, nil
}

// trivyEnvDrop are settings that would turn a download into a no-op or send
// it elsewhere.
var trivyEnvDrop = []string{
	"TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_JAVA_DB_UPDATE", "TRIVY_OFFLINE_SCAN",
	"TRIVY_CACHE_DIR", "TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY",
	"TRIVY_DOWNLOAD_DB_ONLY", "TRIVY_DOWNLOAD_JAVA_DB_ONLY",
}

// Fetch implements Source.
func (t *TrivyDB) Fetch(ctx context.Context, dir string, r *Remote, _ core.ContentPin) (*Meta, error) {
	ctx, cancel := context.WithTimeout(ctx, firstDuration(t.Timeout, 20*time.Minute))
	defer cancel()
	var lastErr error
	for _, repo := range strings.Split(r.Ref, ",") {
		args := []string{"image", "--download-db-only", "--no-progress", "--cache-dir", dir, "--db-repository", repo}
		if _, err := run(ctx, t.binary(), args, trivyEnvDrop, nil); err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		r.Source = strings.SplitN(repo, "@", 2)[0]
		break
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if t.JavaDB {
		args := []string{"image", "--download-java-db-only", "--no-progress", "--cache-dir", dir}
		if t.JavaRepository != "" {
			args = append(args, "--java-db-repository", t.JavaRepository)
		}
		if _, err := run(ctx, t.binary(), args, trivyEnvDrop, nil); err != nil {
			return nil, fmt.Errorf("java db: %w", err)
		}
	}
	return &Meta{Digest: r.Digest, Source: r.Source}, nil
}

// trivyVersionInfo is `trivy version -f json`.
type trivyVersionInfo struct {
	Version         string       `json:"Version"`
	VulnerabilityDB *trivyDBMeta `json:"VulnerabilityDB"`
	JavaDB          *trivyDBMeta `json:"JavaDB"`
}

type trivyDBMeta struct {
	Version   int       `json:"Version"`
	UpdatedAt time.Time `json:"UpdatedAt"`
}

// Verify implements Source: trivy itself must read the database's metadata,
// with the schema this trivy uses.
func (t *TrivyDB) Verify(ctx context.Context, dir string, m *Meta) error {
	if _, err := os.Stat(filepath.Join(dir, "db", "trivy.db")); err != nil {
		return errors.New("no db/trivy.db after the download")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := run(ctx, t.binary(), []string{"version", "--cache-dir", dir, "-f", "json"}, trivyEnvDrop, nil)
	if err != nil {
		return err
	}
	var info trivyVersionInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return fmt.Errorf("trivy version: %w", err)
	}
	db := info.VulnerabilityDB
	if db == nil || db.UpdatedAt.IsZero() {
		return errors.New("trivy does not see a vulnerability database")
	}
	if db.Version != trivyDBSchema {
		return fmt.Errorf("database schema %d, this trivy reads %d", db.Version, trivyDBSchema)
	}
	up := db.UpdatedAt.UTC()
	m.UpdatedAt = &up
	m.Version = up.Format(time.RFC3339)
	if m.Digest != "" {
		m.Checks = append(m.Checks, "oci-digest")
	}
	m.Checks = append(m.Checks, "trivy-metadata", fmt.Sprintf("schema-%d", trivyDBSchema))
	if t.JavaDB {
		j := info.JavaDB
		if j == nil || j.UpdatedAt.IsZero() {
			return errors.New("trivy does not see the Java database")
		}
		jup := j.UpdatedAt.UTC()
		m.Also = append(m.Also, Meta{
			Name: core.ContentTrivyJavaDB, Version: jup.Format(time.RFC3339), UpdatedAt: &jup,
			Source: firstNonEmpty(t.JavaRepository, "trivy default"), FetchedAt: time.Now().UTC(),
		})
	}
	return nil
}

// Prepare implements Preparer: without a managed Java DB, a version links
// java-db to a shared directory, so the Java DB trivy downloads by itself
// is kept across database versions.
func (t *TrivyDB) Prepare(versionDir string) error {
	if t.JavaDB || t.Root == "" {
		return nil
	}
	shared := filepath.Join(t.Root, core.ContentTrivyDB, sharedJavaDB)
	if err := os.MkdirAll(shared, 0o755); err != nil {
		return err
	}
	link := filepath.Join(versionDir, "java-db")
	if _, err := os.Lstat(link); err == nil {
		return nil
	}
	return os.Symlink(shared, link)
}

// Baked implements Importer: a trivy cache directory that already holds a
// database (an image built with one, or a cache volume).
func (t *TrivyDB) Baked() (string, *Meta, bool) {
	if t.BakedDir == "" {
		return "", nil, false
	}
	raw, err := os.ReadFile(filepath.Join(t.BakedDir, "db", "metadata.json"))
	if err != nil {
		return "", nil, false
	}
	var md trivyDBMeta
	if json.Unmarshal(raw, &md) != nil || md.UpdatedAt.IsZero() || md.Version != trivyDBSchema {
		return "", nil, false
	}
	up := md.UpdatedAt.UTC()
	return t.BakedDir, &Meta{
		Version: up.Format(time.RFC3339), UpdatedAt: &up, Source: "image",
		Checks: []string{"trivy-metadata"},
	}, true
}

func firstDuration(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
