package nuclei

// A private nuclei configuration directory per run over a managed template
// set (api docs/rfcs/RFC-031-scanner-content-and-managed-sensor-updates.md).
//
// nuclei reads three things from its configuration directory
// ($XDG_CONFIG_HOME/nuclei, else $HOME/.config/nuclei), not from -t:
//
//   - .templates-config.json: its templates directory. nuclei confines
//     template helper files (payload wordlists under helpers/, workflow
//     subtemplates) to that directory. A template set passed with -t from
//     anywhere else loses every template that loads a helper: nuclei
//     v3.11.1 reports them as "templates with runtime error" ("access to
//     helper file ... denied") and never runs them. That was 262 templates
//     of nuclei-templates v10.4.9 on every sensor scan of the managed set.
//   - the templates release version it prints and records.
//   - .nuclei-ignore: the template release's own exclusion list (tags dos,
//     fuzz, bruteforce, local, and templates with weak matchers). nuclei
//     copies it there when it installs templates itself; a managed set never
//     had it, so nuclei logged "Could not read nuclei-ignore file" twice per
//     run and ran the denial-of-service and brute-force templates the
//     release excludes by default.
//
// The sensor's own HOME is shared by concurrent scans that may hold
// different template versions, so each run gets its own directory, written
// before the run and removed after it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// IgnoreFileName is nuclei's exclusion list, in its config directory
	// and at the root of a nuclei-templates release.
	IgnoreFileName = ".nuclei-ignore"
	// templatesConfigName is nuclei's record of its templates directory
	// and release version.
	templatesConfigName = ".templates-config.json"
	// maxIgnoreFileBytes bounds the release's ignore file read (v10.4.9's
	// is 1.5 KB).
	maxIgnoreFileBytes = 256 << 10
)

// BaselineIgnoreTags are always excluded from a run of the sensor's own
// template set: the tags ProjectDiscovery's default .nuclei-ignore excludes.
// A release's own list is used as well, never instead: a release that drops
// a tag from its list does not make the sensor run denial-of-service or
// brute-force templates against a customer's targets.
var BaselineIgnoreTags = []string{"dos", "local", "fuzz", "bruteforce", "txt-service"}

// templatesVersionRE accepts a release tag or the sensor's own version
// names ("image", "local-<digest prefix>"); anything else is left out of
// the config rather than written into a JSON file nuclei parses.
var templatesVersionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)

// IgnoreList is a .nuclei-ignore file.
type IgnoreList struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReleaseIgnore is the exclusion list for runs over templateDir: the
// release's own .nuclei-ignore, plus BaselineIgnoreTags. A missing,
// oversized, non-regular or unparsable release file leaves the baseline
// alone; release says which ("release", or the reason it was not used).
func ReleaseIgnore(templateDir string) (list IgnoreList, release string) {
	list, release = IgnoreList{}, "release"
	raw, err := readRegular(filepath.Join(templateDir, IgnoreFileName), maxIgnoreFileBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		release = "none in the template set"
	case err != nil:
		release = "unusable: " + err.Error()
	default:
		if err := yaml.Unmarshal(raw, &list); err != nil {
			list, release = IgnoreList{}, "unparsable: "+err.Error()
		}
	}
	for _, t := range BaselineIgnoreTags {
		if !slices.Contains(list.Tags, t) {
			list.Tags = append(list.Tags, t)
		}
	}
	list.Files = slices.DeleteFunc(list.Files, func(f string) bool {
		// A path nuclei would resolve outside the template set, or a
		// flag-shaped entry, is not an exclusion this list may carry.
		return f == "" || filepath.IsAbs(f) || !filepath.IsLocal(f)
	})
	return list, release
}

// ConfigHome is a private nuclei configuration directory for runs over one
// template set. Pass Env to the nuclei process and Close it afterwards.
type ConfigHome struct {
	// Dir is the directory XDG_CONFIG_HOME names; nuclei uses Dir/nuclei.
	Dir string
	// Ignore is where the exclusion list came from (see ReleaseIgnore).
	Ignore string
}

// NewConfigHome writes a nuclei configuration for templateDir (absolute,
// the template set's root) at release version into a new 0700 temporary
// directory.
func NewConfigHome(templateDir, version string) (*ConfigHome, error) {
	if templateDir == "" {
		return nil, errors.New("nuclei config: no template directory")
	}
	abs, err := filepath.Abs(templateDir)
	if err != nil {
		return nil, fmt.Errorf("nuclei config: %w", err)
	}
	dir, err := os.MkdirTemp("", "nuclei-config-*") // 0700
	if err != nil {
		return nil, fmt.Errorf("nuclei config: %w", err)
	}
	home := &ConfigHome{Dir: dir}
	fail := func(err error) (*ConfigHome, error) {
		_ = home.Close()
		return nil, fmt.Errorf("nuclei config: %w", err)
	}
	cfgDir := filepath.Join(dir, "nuclei")
	if err := os.Mkdir(cfgDir, 0o700); err != nil {
		return fail(err)
	}

	cfg := map[string]string{"nuclei-templates-directory": abs}
	if templatesVersionRE.MatchString(version) {
		cfg["nuclei-templates-version"] = version
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, templatesConfigName), raw, 0o600); err != nil {
		return fail(err)
	}

	list, from := ReleaseIgnore(abs)
	home.Ignore = from
	raw, err = yaml.Marshal(list)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, IgnoreFileName), raw, 0o600); err != nil {
		return fail(err)
	}
	return home, nil
}

// Env is the environment that points nuclei at this configuration.
func (h *ConfigHome) Env() map[string]string {
	if h == nil {
		return nil
	}
	return map[string]string{"XDG_CONFIG_HOME": h.Dir}
}

// Close removes the directory (what nuclei wrote into it included).
func (h *ConfigHome) Close() error {
	if h == nil || h.Dir == "" {
		return nil
	}
	return os.RemoveAll(h.Dir)
}

// readRegular reads a regular file (not a symlink, a device or a
// directory) of at most limit bytes.
func readRegular(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	f, err := os.Open(path) //nolint:gosec // a path under the sensor's own template set
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

var (
	parseErrorRE   = regexp.MustCompile(`Error occurred parsing template ([^:]+):`)
	missingTplRE   = regexp.MustCompile(`Could not find template '([^']+)'`)
	maxErrorLength = 200
)

// ValidateErrors lists what `nuclei -validate` reported as failing, from its
// stderr: the template path of each "[ERR]" line that names one (a template
// that does not compile, a workflow subtemplate that is missing), else the
// line itself. Each appears once, in the order reported.
func ValidateErrors(stderr []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(ansiEscape.ReplaceAllString(string(stderr), ""), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[ERR]") {
			continue
		}
		item := strings.TrimSpace(strings.TrimPrefix(line, "[ERR]"))
		if m := parseErrorRE.FindStringSubmatch(line); m != nil {
			item = m[1]
		} else if m := missingTplRE.FindStringSubmatch(line); m != nil {
			item = m[1]
		} else if len(item) > maxErrorLength {
			item = item[:maxErrorLength] + "..."
		}
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
