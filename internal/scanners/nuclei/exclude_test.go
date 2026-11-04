package nuclei

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Each exclusion becomes an exact nuclei entry: an address or range as is,
// a host as an anchored quoted expression (nuclei reads host entries as
// regular expressions), a wildcard as any subdomain.
func TestExcludeEntry(t *testing.T) {
	ok := map[string]string{
		"10.0.0.0/8":                "10.0.0.0/8",
		"10.1.2.3/8":                "10.0.0.0/8",
		"203.0.113.9":               "203.0.113.9",
		"2001:db8::/32":             "2001:db8::/32",
		"[2001:db8::1]:443":         "2001:db8::1",
		"a.example.com":             `^a\.example\.com$`,
		"A.Example.com.":            `^a\.example\.com$`,
		"a.example.com:8443":        `^a\.example\.com$`,
		"https://a.example.com/x?y": `^a\.example\.com$`,
		"*.example.com":             `^.+\.example\.com$`,
		"intranet_host":             `^intranet_host$`,
	}
	for in, want := range ok {
		got, err := excludeEntry(in)
		if err != nil || got != want {
			t.Errorf("excludeEntry(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", " ", "a.example.com/admin", "a.*.example.com", "a,b.example.com",
		"a b", "/etc/hosts", "**", "*.", "a..b", "-x.example.com", "http://", "a.example.com\n-t"} {
		if got, err := excludeEntry(in); err == nil {
			t.Errorf("excludeEntry(%q) = %q, want an error", in, got)
		}
	}
}

// SECURITY: a host entry matches that host only, never another name that
// merely contains it (nuclei compiles it unanchored).
func TestExcludeEntryIsExact(t *testing.T) {
	e, _ := excludeEntry("a.example.com")
	re := regexp.MustCompile(e)
	for host, want := range map[string]bool{
		"a.example.com": true, "aXexample.com": false, "xa.example.com": false, "a.example.com.evil": false,
	} {
		if re.MatchString(host) != want {
			t.Errorf("%q matches %q = %v, want %v", e, host, !want, want)
		}
	}
	w, _ := excludeEntry("*.example.com")
	re = regexp.MustCompile(w)
	for host, want := range map[string]bool{
		"a.example.com": true, "b.a.example.com": true, "example.com": false, "a.example.com.evil": false, "aexample.com": false,
	} {
		if re.MatchString(host) != want {
			t.Errorf("%q matches %q = %v, want %v", w, host, !want, want)
		}
	}
}

// The job's exclusions reach nuclei as -exclude-hosts. Before, the adapter
// passed -exclude, which nuclei v3 does not define: the run aborted.
func TestExcludeBecomesExcludeHosts(t *testing.T) {
	args := NewScanner().buildArgs("https://example.com", &core.ScanOptions{Exclude: []string{"10.0.0.0/8", "b.example.com", "b.example.com"}})
	if slices.Contains(args, "-exclude") {
		t.Fatalf("undefined -exclude flag in %q", args)
	}
	var got []string
	for i, a := range args {
		if a == "-exclude-hosts" {
			got = append(got, args[i+1])
		}
	}
	if !slices.Equal(got, []string{"10.0.0.0/8", `^b\.example\.com$`}) {
		t.Fatalf("-exclude-hosts = %q", got)
	}
}

// SECURITY: an exclusion the sensor cannot honour fails the scan instead of
// being dropped.
func TestExcludeRefusedFailsTheScan(t *testing.T) {
	bin, argsFile := fakeToolNuclei(t, 1)
	_, err := scanner(bin).Scan(context.Background(), "http://203.0.113.10", &core.ScanOptions{Exclude: []string{"a.example.com/admin"}})
	if err == nil || !strings.Contains(err.Error(), "exclusion") {
		t.Fatalf("err = %v, want the exclusion refused", err)
	}
	if _, statErr := os.Stat(argsFile); statErr == nil {
		t.Fatal("nuclei ran with an exclusion it cannot honour")
	}
}

// SECURITY: out of process, the exclusions and the settings' retries
// reach the tool child. Before, the child lost the exclusions (not in the
// task's run options) and a retries setting of 0 (an unexported flag).
func TestOutOfProcessCarriesExcludeAndSettings(t *testing.T) {
	bin, argsFile := fakeToolNuclei(t, 1)
	t.Setenv(toolrun.EnvRuntime, "")
	opts := &core.ScanOptions{
		Exclude:  []string{"*.internal.example.com"},
		Settings: sensorSettings(t, map[string]any{"retries": 0, "response_read_kb": 2048, "response_save_kb": 256}),
	}
	if _, err := scanner(bin).Scan(context.Background(), "http://203.0.113.10", opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(raw))
	for flag, want := range map[string]string{
		"-exclude-hosts":      `^.+\.internal\.example\.com$`,
		"-retries":            "0",
		"-response-size-read": "2097152",
		"-response-size-save": "262144",
	} {
		if v := settingFlag(args, flag); v != want {
			t.Errorf("%s = %q, want %q (args %q)", flag, v, want, args)
		}
	}
}

func sensorSettings(t *testing.T, values map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: values})
	if err != nil {
		t.Fatalf("resolve %v: %v", values, err)
	}
	return ts
}

// The response size settings map to nuclei's flags; the evidence size
// never exceeds the read size; without settings nuclei's own apply.
func TestSettings_ResponseSizes(t *testing.T) {
	sc0, err := NewScanner().forScan(&core.ScanOptions{Settings: sensorSettings(t, map[string]any{"response_read_kb": 64, "response_save_kb": 512})})
	if err != nil {
		t.Fatal(err)
	}
	got := sc0.buildArgs("https://example.com", nil)
	if v := settingFlag(got, "-response-size-read"); v != "65536" {
		t.Errorf("-response-size-read = %q", v)
	}
	if v := settingFlag(got, "-response-size-save"); v != "65536" {
		t.Errorf("-response-size-save = %q, want capped at the read size", v)
	}
	plain := NewScanner().buildArgs("https://example.com", nil)
	if slices.Contains(plain, "-response-size-read") || slices.Contains(plain, "-response-size-save") {
		t.Errorf("size flags without settings: %q", plain)
	}
	if !slices.Contains(plain, "-omit-template") {
		t.Errorf("-omit-template missing: %q", plain)
	}
	sc, err := NewScanner().forScan(&core.ScanOptions{Settings: scanSettings(t, map[string]any{})})
	if err != nil {
		t.Fatal(err)
	}
	if sc.ResponseReadKB != 10240 || sc.ResponseSaveKB != 1024 {
		t.Errorf("defaults = %d/%d KiB, want nuclei's own 10240/1024", sc.ResponseReadKB, sc.ResponseSaveKB)
	}
}

// The response sizes are bounded by the schema: a scan cannot make nuclei
// read unbounded responses, and the read limit is a sensor-level setting.
func TestSettings_ResponseSizeBounds(t *testing.T) {
	schema := NewScanner().SettingsSchema()
	for _, values := range []map[string]any{
		{"response_read_kb": 1 << 20}, {"response_save_kb": 4096}, {"response_save_kb": 0},
	} {
		if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: values}); err == nil {
			t.Errorf("%v resolved, want refused", values)
		}
	}
	if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"response_read_kb": 128}}); err == nil {
		t.Error("a scan set the sensor-level response_read_kb")
	}
}

// Every flag the adapter can put on nuclei's command line is one the real
// nuclei defines (it aborts on an undefined flag). Skipped without a real
// binary (NUCLEI_REAL_BIN; CI sets it).
func TestRealNucleiDefinesEveryFlag(t *testing.T) {
	bin := os.Getenv(EnvRealNuclei)
	if bin == "" {
		t.Skip(EnvRealNuclei + " not set")
	}
	dir := t.TempDir()
	tpl := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(tpl, []byte("id: flags-check\ninfo:\n  name: flags check\n  author: openctem\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n    matchers:\n      - type: status\n        status: [200]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewScanner()
	s.Binary = bin
	s.TemplateDir = tpl
	s.ExcludeIDs, s.Severity = []string{"x"}, []string{"info"}
	// The test template is unsigned; -disable-unsigned-templates is checked
	// by its own run below.
	s.DisableUnsignedTemplates = false
	s.Headers = []string{"X-Test: 1"}
	s.FollowRedirects, s.MaxRedirects = true, 3
	s.Headless, s.PageTimeout, s.ShowBrowser, s.HeadlessConcurrency = true, 5, false, 2
	s.SystemResolvers, s.Retries, s.StopAtFirstMatch, s.NoColor, s.Silent = true, 2, true, true, true
	s.RequestTimeout, s.ScanStrategy, s.MaxHostErrors = 1, "host-spray", 5
	s.ResponseReadKB, s.ResponseSaveKB = 128, 64
	args := s.buildArgsFor("http://127.0.0.1:1", "", &core.ScanOptions{Exclude: []string{"10.0.0.0/8", "*.example.com", "a.example.com"}}, passOwn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append(args, "-duc", "-headless=false")...) //nolint:gosec // test binary
	cmd.Env = append(os.Environ(), "HOME="+dir)
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "flag provided but not defined") || strings.Contains(string(out), "[FTL]") {
		t.Fatalf("nuclei refused the adapter's arguments %q:\n%s", args, out)
	}
	// The filters and the signature check, which leave no template to run.
	s.DisableUnsignedTemplates = true
	s.Tags, s.Author = []string{"cve"}, []string{"openctem"}
	args = s.buildArgsFor("http://127.0.0.1:1", "", nil, passOwn)
	out, _ = exec.CommandContext(ctx, bin, append(args, "-duc", "-headless=false")...).CombinedOutput() //nolint:gosec // test binary
	if strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf("nuclei refused the adapter's arguments %q:\n%s", args, out)
	}
}
