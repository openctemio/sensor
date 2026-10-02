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

	"github.com/openctemio/sdk-go/pkg/core"
)

// DefaultSemgrepRegistry is where rulesets are fetched (GET <registry>/c/<ruleset>).
const DefaultSemgrepRegistry = "https://semgrep.dev"

const maxSemgrepRulesBytes = 64 << 20

var rulesetRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

// SemgrepRules is a pinned semgrep rules bundle. It is managed only when
// rulesets are chosen (policy or Rulesets) or a local rules path is set:
// otherwise semgrep keeps fetching its rules from the registry on every
// scan (--config auto), and the sensor reports that as unmanaged content.
type SemgrepRules struct {
	Binary   string // semgrep binary (default "semgrep"), for the check
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
}

// Name implements Source.
func (s *SemgrepRules) Name() string { return core.ContentSemgrepRules }

// Tool implements Source.
func (s *SemgrepRules) Tool() string { return "semgrep" }

func (s *SemgrepRules) rulesets(pin core.ContentPin) []string {
	if len(pin.Rulesets) > 0 {
		return pin.Rulesets
	}
	return s.Rulesets
}

// Managed implements Source.
func (s *SemgrepRules) Managed(pin core.ContentPin) bool {
	return s.LocalPath != "" || len(s.rulesets(pin)) > 0
}

// UnmanagedInfo implements Unmanaged.
func (s *SemgrepRules) UnmanagedInfo() core.ContentInfo {
	return core.ContentInfo{Name: core.ContentSemgrepRules, Managed: false, Source: "semgrep registry (fetched per scan, --config auto)"}
}

// Resolve implements Source. A registry cannot tell what a ruleset holds
// without fetching it, so the comparison happens after Fetch.
func (s *SemgrepRules) Resolve(_ context.Context, pin core.ContentPin) (*Remote, error) {
	if s.LocalPath != "" {
		return &Remote{Ref: s.LocalPath, Source: s.LocalPath}, nil
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
func (s *SemgrepRules) Fetch(ctx context.Context, dir string, r *Remote, _ core.ContentPin) (*Meta, error) {
	ctx, cancel := context.WithTimeout(ctx, firstDuration(s.Timeout, 10*time.Minute))
	defer cancel()
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
	empty, err := os.MkdirTemp("", "semgrep-check-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(empty) }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	out, err := run(ctx, firstNonEmpty(s.Binary, "semgrep"),
		[]string{"scan", "--config", dir, "--metrics=off", "--disable-version-check", "--json", "--quiet", empty}, nil, nil)
	if err != nil {
		return fmt.Errorf("semgrep rejects the rules: %w", err)
	}
	var res struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return fmt.Errorf("semgrep check: %w", err)
	}
	if len(res.Errors) > 0 {
		return fmt.Errorf("semgrep reports %d rule errors", len(res.Errors))
	}
	m.Checks = append(m.Checks, "semgrep-load")
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
