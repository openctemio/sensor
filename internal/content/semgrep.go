package content

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/blobsig"
	"github.com/openctemio/sdk-go/pkg/core"
)

// DefaultSemgrepRegistry is where rulesets are fetched (GET <registry>/c/<ruleset>).
const DefaultSemgrepRegistry = "https://semgrep.dev"

// The OpenCTEM rules pack (github.com/openctemio/sast-rules): the default
// rules when no local path and no rulesets are chosen. Each release is a
// tarball signed (cosign keyless) by the repository's release workflow;
// the bundle is installed only when that signature verifies.
const (
	DefaultPackLatestURL   = "https://api.github.com/repos/openctemio/sast-rules/releases/latest"
	DefaultPackTagURL      = "https://api.github.com/repos/openctemio/sast-rules/releases/tags/{version}"
	DefaultPackDownloadURL = "https://github.com/openctemio/sast-rules/releases/download/{version}/sast-rules-{bare_version}.tar.gz"
	packRepo               = "openctemio/sast-rules"
	packWorkflow           = ".github/workflows/release.yml"
	maxPackBytes           = 64 << 20
)

var packTagRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// packSigner is the identity a pack release must be signed by: the release
// workflow of the pack repository at that release's tag.
func packSigner(tag string) blobsig.Signer {
	return blobsig.GitHubWorkflow(packRepo, packWorkflow, "refs/tags/"+tag)
}

const maxSemgrepRulesBytes = 64 << 20

var rulesetRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

// SemgrepRules is the rules bundle semgrep and opengrep run, always
// managed. Its source, in order: a local rules path (air-gapped); the
// registry rulesets the policy or the operator chose (fetched under the
// registry's licence, by their choice); otherwise the signed OpenCTEM rules
// pack (a pinned release, or the newest).
type SemgrepRules struct {
	// Engine is the tool that runs the rules and checks a new bundle:
	// "semgrep" (default) or "opengrep". Both read the same rules.
	Engine   string
	Binary   string // the engine's binary (default: the engine's name), for the check
	Registry string // registry base URL
	// Rulesets are fetched when the policy names none.
	Rulesets []string
	// LocalPath is a rules file or directory installed as is (air-gapped).
	LocalPath string
	Fetcher   *Fetcher
	// SkipCheck skips running semgrep over the rules (the Go-level check
	// still runs).
	SkipCheck bool
	Timeout   time.Duration
	// PackVersion pins a release of the rules pack (vX.Y.Z) when the policy
	// pins none. PackLatestURL, PackTagURL and PackDownloadURL default to the
	// pack's GitHub releases; a mirror may replace them (the signature is
	// still checked against the pack's release workflow).
	PackVersion     string
	PackLatestURL   string
	PackTagURL      string
	PackDownloadURL string
	// verifyPack checks a pack's signature bundle (tests replace it).
	verifyPack func(sha256Digest, bundle []byte, tag string) error
}

// Name implements Source.
func (s *SemgrepRules) Name() string { return core.ContentSemgrepRules }

// Tool implements Source.
func (s *SemgrepRules) Tool() string { return s.engine() }

func (s *SemgrepRules) engine() string {
	if s.Engine == EngineOpengrep {
		return EngineOpengrep
	}
	return "semgrep"
}

// EngineOpengrep names opengrep as the rules' engine.
const EngineOpengrep = "opengrep"

func (s *SemgrepRules) rulesets(pin core.ContentPin) []string {
	if len(pin.Rulesets) > 0 {
		return pin.Rulesets
	}
	return s.Rulesets
}

func (s *SemgrepRules) usesPack(pin core.ContentPin) bool {
	return s.LocalPath == "" && len(s.rulesets(pin)) == 0
}

// Resolve implements Source. A registry cannot tell what a ruleset holds
// without fetching it, so the comparison happens after Fetch.
func (s *SemgrepRules) Resolve(ctx context.Context, pin core.ContentPin) (*Remote, error) {
	if s.LocalPath != "" {
		return &Remote{Ref: s.LocalPath, Source: s.LocalPath}, nil
	}
	if s.usesPack(pin) {
		return s.resolvePack(ctx, pin)
	}
	rs := s.rulesets(pin)
	for _, r := range rs {
		if !rulesetRE.MatchString(r) || strings.Contains(r, "..") {
			return nil, fmt.Errorf("invalid ruleset %q", r)
		}
	}
	reg := strings.TrimRight(firstNonEmpty(s.Registry, DefaultSemgrepRegistry), "/")
	return &Remote{Ref: strings.Join(rs, ","), Source: reg + " " + strings.Join(rs, ",")}, nil
}

// Fetch implements Source.
func (s *SemgrepRules) Fetch(ctx context.Context, dir string, r *Remote, pin core.ContentPin) (*Meta, error) {
	ctx, cancel := context.WithTimeout(ctx, firstDuration(s.Timeout, 10*time.Minute))
	defer cancel()
	if s.usesPack(pin) {
		return s.fetchPack(ctx, dir, r)
	}
	if s.LocalPath != "" {
		fi, err := os.Stat(s.LocalPath)
		if err != nil {
			return nil, err
		}
		if fi.IsDir() {
			if _, err := copyTree(s.LocalPath, dir); err != nil {
				return nil, err
			}
		} else if err := copyFile(s.LocalPath, filepath.Join(dir, "rules.yaml")); err != nil {
			return nil, err
		}
	} else {
		reg := strings.TrimRight(firstNonEmpty(s.Registry, DefaultSemgrepRegistry), "/")
		for _, rs := range strings.Split(r.Ref, ",") {
			raw, err := s.Fetcher.get(ctx, reg+"/c/"+rs, maxSemgrepRulesBytes)
			if err != nil {
				return nil, fmt.Errorf("ruleset %s: %w", rs, err)
			}
			name := strings.NewReplacer("/", "_", ".", "_").Replace(rs) + ".yaml"
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil { //nolint:gosec // rules are not secret
				return nil, err
			}
		}
	}
	dg, err := treeDigest(dir)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &Meta{Version: "sha256:" + dg[7:19], Digest: dg, UpdatedAt: &now, FetchedAt: now, Source: r.Source}, nil
}

// resolvePack names the pack release to install: the pinned tag, or the
// newest release.
func (s *SemgrepRules) resolvePack(ctx context.Context, pin core.ContentPin) (*Remote, error) {
	tag := firstNonEmpty(pin.Version, s.PackVersion)
	var published *time.Time
	if tag == "" {
		var err error
		tag, published, err = githubRelease(ctx, s.Fetcher, firstNonEmpty(s.PackLatestURL, DefaultPackLatestURL))
		if err != nil {
			return nil, fmt.Errorf("rules pack: %w", err)
		}
	} else if packTagRE.MatchString(tag) {
		// A pinned release: its own date when the lookup works (the
		// signature, not this, decides whether it is installed).
		if _, pub, err := githubRelease(ctx, s.Fetcher, expandVersion(firstNonEmpty(s.PackTagURL, DefaultPackTagURL), tag)); err == nil {
			published = pub
		}
	}
	if !packTagRE.MatchString(tag) {
		return nil, fmt.Errorf("invalid rules pack version %q (want vX.Y.Z)", tag)
	}
	u := expandVersion(firstNonEmpty(s.PackDownloadURL, DefaultPackDownloadURL), tag)
	return &Remote{Version: tag, UpdatedAt: published, Ref: u, Source: "openctem sast-rules " + tag}, nil
}

// fetchPack downloads a pack release and its signature bundle, installs it
// only when the bundle verifies for this archive and the pack's release
// workflow at this tag, and extracts the rules.
func (s *SemgrepRules) fetchPack(ctx context.Context, dir string, r *Remote) (*Meta, error) {
	archive := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+".tar.gz")
	defer func() { _ = os.Remove(archive) }()
	sum, err := s.Fetcher.download(ctx, r.Ref, archive, maxPackBytes)
	if err != nil {
		return nil, fmt.Errorf("rules pack: %w", err)
	}
	bundle, err := s.Fetcher.get(ctx, r.Ref+".sigstore.json", blobsig.MaxBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("rules pack signature: %w", err)
	}
	digest, err := hex.DecodeString(sum)
	if err != nil {
		return nil, err
	}
	verify := s.verifyPack
	if verify == nil {
		verify = func(d, b []byte, tag string) error { return blobsig.VerifyDigest(d, b, packSigner(tag)) }
	}
	if err := verify(digest, bundle, r.Version); err != nil {
		return nil, fmt.Errorf("rules pack %s: signature: %w", r.Version, err)
	}
	if _, err := extractTarGz(archive, dir); err != nil {
		return nil, fmt.Errorf("rules pack: extract: %w", err)
	}
	now := time.Now().UTC()
	return &Meta{Version: r.Version, Digest: "sha256:" + sum, UpdatedAt: r.UpdatedAt, FetchedAt: now, Source: r.Source,
		Checks: []string{"sha256", "sigstore"}}, nil
}

// Verify implements Source: every file is a rules document with rules that
// have ids, and semgrep accepts the whole bundle.
func (s *SemgrepRules) Verify(ctx context.Context, dir string, m *Meta) error {
	rules := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		raw, err := os.ReadFile(path) //nolint:gosec // inside the staging dir
		if err != nil {
			return err
		}
		var doc struct {
			Rules []map[string]any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		if len(doc.Rules) == 0 {
			return fmt.Errorf("%s: no rules", filepath.Base(path))
		}
		for i, r := range doc.Rules {
			if id, _ := r["id"].(string); id == "" {
				return fmt.Errorf("%s: rule %d has no id", filepath.Base(path), i)
			}
		}
		rules += len(doc.Rules)
		return nil
	})
	if err != nil {
		return err
	}
	if rules == 0 {
		return errors.New("no rules")
	}
	m.Checks = append(m.Checks, fmt.Sprintf("rules-%d", rules))
	if s.SkipCheck {
		return nil
	}
	empty, err := os.MkdirTemp("", "rules-check-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(empty) }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	eng := s.engine()
	args := []string{"scan", "--config", dir, "--disable-version-check", "--json", "--quiet", empty}
	var env map[string]string
	if eng == EngineOpengrep {
		// opengrep has no metrics; it keeps its log in
		// $XDG_CONFIG_HOME/.opengrep, here the check's own directory.
		env = map[string]string{"XDG_CONFIG_HOME": empty}
	} else {
		args = append(args[:3], append([]string{"--metrics=off"}, args[3:]...)...)
	}
	out, err := run(ctx, firstNonEmpty(s.Binary, eng), args, nil, env)
	if err != nil {
		return fmt.Errorf("%s rejects the rules: %w", eng, err)
	}
	var res struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return fmt.Errorf("%s check: %w", eng, err)
	}
	if len(res.Errors) > 0 {
		return fmt.Errorf("%s reports %d rule errors", eng, len(res.Errors))
	}
	m.Checks = append(m.Checks, eng+"-load")
	return nil
}

// treeDigest is the sha256 over a directory's files (sorted relative paths
// and contents), as "sha256:<hex>".
func treeDigest(dir string) (string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			paths = append(paths, path)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		rel, _ := filepath.Rel(dir, p)
		raw, err := os.ReadFile(p) //nolint:gosec // inside the content dir
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(raw)
		_, _ = fmt.Fprintf(h, "%s %s\n", hex.EncodeToString(sum[:]), filepath.ToSlash(rel))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
