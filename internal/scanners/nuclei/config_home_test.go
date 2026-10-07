package nuclei

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/scanners/importparse"
	"gopkg.in/yaml.v3"
)

// releaseIgnore is nuclei-templates v10.4.9's own .nuclei-ignore, abridged.
const releaseIgnore = `tags:
  - "dos"
  - "local"
  - "fuzz"
  - "bruteforce"
  - "txt-service"
files:
  - http/cves/2019/CVE-2019-14696.yaml
  - dns/soa-detect.yaml
`

func readIgnore(t *testing.T, home *ConfigHome) IgnoreList {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home.Dir, "nuclei", IgnoreFileName))
	if err != nil {
		t.Fatal(err)
	}
	var l IgnoreList
	if err := yaml.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func readTemplatesConfig(t *testing.T, home *ConfigHome) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home.Dir, "nuclei", templatesConfigName))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The private configuration names the managed directory and release (so
// nuclei resolves helper files there and prints the release), carries the
// release's exclusion list, is private to the run and removed after it.
func TestNewConfigHome(t *testing.T) {
	tpl := t.TempDir()
	if err := os.WriteFile(filepath.Join(tpl, IgnoreFileName), []byte(releaseIgnore), 0o644); err != nil {
		t.Fatal(err)
	}
	home, err := NewConfigHome(tpl, "v10.4.9")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(home.Dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("config dir %v mode %v, want 0700", err, fi.Mode().Perm())
	}
	if got := home.Env()["XDG_CONFIG_HOME"]; got != home.Dir {
		t.Fatalf("Env = %v", home.Env())
	}
	cfg := readTemplatesConfig(t, home)
	if cfg["nuclei-templates-directory"] != tpl || cfg["nuclei-templates-version"] != "v10.4.9" {
		t.Fatalf("templates config %v", cfg)
	}
	l := readIgnore(t, home)
	if !slices.Contains(l.Files, "dns/soa-detect.yaml") || !slices.Contains(l.Tags, "dos") || home.Ignore != "release" {
		t.Fatalf("ignore list %+v (%s)", l, home.Ignore)
	}
	if err := home.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home.Dir); !os.IsNotExist(err) {
		t.Fatalf("config dir left behind: %v", err)
	}
}

// A release that drops a dangerous tag from its list, or ships none, still
// excludes the baseline: the sensor never runs denial-of-service or
// brute-force templates by default.
func TestReleaseIgnoreKeepsBaseline(t *testing.T) {
	tpl := t.TempDir()
	if err := os.WriteFile(filepath.Join(tpl, IgnoreFileName), []byte("tags:\n  - \"cve\"\nfiles:\n  - ../../etc/passwd\n  - /abs.yaml\n  - ok/x.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, from := ReleaseIgnore(tpl)
	for _, tag := range append([]string{"cve"}, BaselineIgnoreTags...) {
		if !slices.Contains(l.Tags, tag) {
			t.Errorf("tag %q missing from %v", tag, l.Tags)
		}
	}
	if !slices.Equal(l.Files, []string{"ok/x.yaml"}) || from != "release" {
		t.Errorf("files %v (%s): entries outside the template set must be dropped", l.Files, from)
	}

	l, from = ReleaseIgnore(t.TempDir())
	if !slices.Equal(l.Tags, BaselineIgnoreTags) || len(l.Files) != 0 || !strings.Contains(from, "none") {
		t.Errorf("no release file: %+v (%s)", l, from)
	}
}

// The release's ignore file is read only as a regular, bounded file: a
// symlink (to the sensor's secrets, say) or garbage leaves the baseline.
func TestReleaseIgnoreRefusesSymlinkAndGarbage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("tags:\n  - \"leak\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(tpl, IgnoreFileName)); err != nil {
		t.Fatal(err)
	}
	l, from := ReleaseIgnore(tpl)
	if slices.Contains(l.Tags, "leak") || !strings.HasPrefix(from, "unusable") {
		t.Fatalf("symlinked ignore file followed: %+v (%s)", l, from)
	}

	tpl = t.TempDir()
	if err := os.WriteFile(filepath.Join(tpl, IgnoreFileName), []byte("tags: [unclosed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if l, from = ReleaseIgnore(tpl); !slices.Equal(l.Tags, BaselineIgnoreTags) || !strings.HasPrefix(from, "unparsable") {
		t.Fatalf("garbage ignore file: %+v (%s)", l, from)
	}
}

// A version that is not a plain release name never reaches nuclei's JSON.
func TestNewConfigHomeDropsOddVersion(t *testing.T) {
	for _, v := range []string{"", "v1\"}", "../x", strings.Repeat("a", 80)} {
		home, err := NewConfigHome(t.TempDir(), v)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := readTemplatesConfig(t, home)["nuclei-templates-version"]; ok {
			t.Errorf("version %q written as %q", v, got)
		}
		_ = home.Close()
	}
	if _, err := NewConfigHome("", "v1"); err == nil {
		t.Fatal("empty template dir accepted")
	}
}

// What nuclei v3.11.1 printed for the managed set before the fix, and a
// missing workflow subtemplate: both are validation failures.
func TestValidateErrors(t *testing.T) {
	stderr := "\x1b[31mERR\x1b[0m ignored without brackets\n" +
		"[\x1b[31mERR\x1b[0m] Error occurred parsing template /c/v/http/technologies/wordpress/plugins/a.yaml: could not compile request: could not parse payloads: could not load payload file: cause=\"access to helper file /c/v/helpers/wordpress/plugins/a.txt denied\"\n" +
		"[ERR] Error occurred parsing template /c/v/http/technologies/wordpress/plugins/a.yaml: again\n" +
		"[ERR] Could not find template 'http/technologies/tech-detect.yaml': could not find template file\n" +
		"[WRN] Skipping workflow subtemplate: -code flag is required\n" +
		"[FTL] Could not validate templates: errors occurred during template validation\n"
	got := ValidateErrors([]byte(stderr))
	want := []string{"/c/v/http/technologies/wordpress/plugins/a.yaml", "http/technologies/tech-detect.yaml"}
	if !slices.Equal(got, want) {
		t.Fatalf("ValidateErrors = %q, want %q", got, want)
	}
	if got := ValidateErrors([]byte("[INF] ok\n[WRN] Skipping 8 unsigned template[s]\n")); len(got) != 0 {
		t.Fatalf("no errors expected, got %q", got)
	}
}

// stubNucleiEnv is a nuclei stand-in that reports the configuration it was
// started with: it copies $XDG_CONFIG_HOME/nuclei's files into report and
// prints line on stdout.
func stubNucleiEnv(t *testing.T, report, line string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "out.txt"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "nuclei")
	script := `#!/bin/sh
mkdir -p '` + report + `'
echo "${XDG_CONFIG_HOME:-unset}" > '` + report + `/xdg'
if [ -n "$XDG_CONFIG_HOME" ]; then
  cp "$XDG_CONFIG_HOME/nuclei/.templates-config.json" "$XDG_CONFIG_HOME/nuclei/.nuclei-ignore" '` + report + `/'
fi
cat '` + filepath.Join(dir, "out.txt") + `'
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test stand-in must be executable
		t.Fatal(err)
	}
	return bin
}

// A scan of a managed template set runs nuclei with its own configuration
// for that set (directory, release, exclusion list), removed after the run;
// each result carries the digest of its template file.
func TestScanManagedTemplatesConfigAndDigest(t *testing.T) {
	tpl := t.TempDir()
	tplFile := filepath.Join(tpl, "http", "exposures", "git-config.yaml")
	if err := os.MkdirAll(filepath.Dir(tplFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tplFile, []byte("id: git-config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report")
	line := `{"template-id":"git-config","template":"http/exposures/git-config.yaml","template-path":"` + tplFile + `","info":{"name":"Git Config","severity":"medium"},"host":"127.0.0.1","matched-at":"http://127.0.0.1:8080/.git/config","type":"http"}` + "\n"

	s := NewScanner()
	s.Binary = stubNucleiEnv(t, report, line)
	s.TemplateDir = tpl
	s.TemplatesVersion = "v10.4.9"
	s.DisableUpdateCheck = true
	res, err := s.Scan(context.Background(), "http://127.0.0.1:8080", nil)
	if err != nil {
		t.Fatal(err)
	}

	xdg, _ := os.ReadFile(filepath.Join(report, "xdg"))
	xdgDir := strings.TrimSpace(string(xdg))
	if xdgDir == "unset" || xdgDir == "" {
		t.Fatal("nuclei ran without a private configuration")
	}
	if _, err := os.Stat(xdgDir); !os.IsNotExist(err) {
		t.Errorf("private configuration %s left behind", xdgDir)
	}
	raw, _ := os.ReadFile(filepath.Join(report, templatesConfigName))
	if !strings.Contains(string(raw), `"nuclei-templates-version":"v10.4.9"`) || !strings.Contains(string(raw), tpl) {
		t.Errorf("templates config %s", raw)
	}
	raw, _ = os.ReadFile(filepath.Join(report, IgnoreFileName))
	if !strings.Contains(string(raw), "dos") {
		t.Errorf("ignore list %s", raw)
	}

	want, _ := TemplateDigest(tplFile, []string{tpl})
	if want == "" || !strings.Contains(string(res.RawOutput), `"template-digest":"`+want+`"`) {
		t.Fatalf("result has no template digest %q: %s", want, res.RawOutput)
	}
	report2, err := importparse.Nuclei().Parse(context.Background(), res.RawOutput, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := report2.Findings[0]
	if f.Properties["template_digest"] != want || f.Properties["template_path"] != "http/exposures/git-config.yaml" {
		t.Fatalf("finding properties %v", f.Properties)
	}
}

// Without a managed set, nuclei keeps its own configuration.
func TestScanUnmanagedKeepsNucleiConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	report := filepath.Join(t.TempDir(), "report")
	s := NewScanner()
	s.Binary = stubNucleiEnv(t, report, "")
	if _, err := s.Scan(context.Background(), "http://127.0.0.1:8080", nil); err != nil {
		t.Fatal(err)
	}
	xdg, _ := os.ReadFile(filepath.Join(report, "xdg"))
	if got := strings.TrimSpace(string(xdg)); got != "unset" {
		t.Fatalf("unmanaged scan got XDG_CONFIG_HOME=%s", got)
	}
}
