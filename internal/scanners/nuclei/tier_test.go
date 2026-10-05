package nuclei

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// SECURITY (RFC-036 T1): every nuclei run excludes the intrusive template
// classes, with or without managed templates, for the sensor's own set and
// for custom templates. Before, a default scan passed no -etags at all.
func TestEveryRunExcludesIntrusiveTemplates(t *testing.T) {
	managed := NewScanner()
	managed.TemplateDir = "/content/nuclei-templates/v10.4.9"
	custom := &core.ScanOptions{CustomTemplateDir: "/tmp/tenant-templates"}

	runs := map[string][]string{
		"default scanner":       NewScanner().buildArgs("https://example.com", nil),
		"managed templates":     managed.buildArgs("https://example.com", &core.ScanOptions{}),
		"own pass with custom":  managed.buildArgsFor("https://example.com", "", custom, passOwn),
		"custom templates pass": managed.buildArgsFor("https://example.com", "", custom, passCustom),
		"list mode":             NewScanner().buildArgsFor("", "/tmp/list.txt", nil, passOwn),
		"dast preset":           NewDAST().buildArgs("https://example.com", nil),
		"takeover preset":       NewTakeoverScanner().buildArgs("https://example.com", nil),
	}
	for name, args := range runs {
		etags := strings.Split(settingFlag(args, "-etags"), ",")
		for _, want := range []string{"intrusive", "default-login", "dos", "fuzz", "bruteforce", "brute-force", "local", "txt-service"} {
			if !slices.Contains(etags, want) {
				t.Errorf("%s: -etags %q does not exclude %q (args %q)", name, etags, want, args)
			}
		}
		if n := strings.Count(strings.Join(args, " "), " -etags "); n != 1 {
			t.Errorf("%s: -etags passed %d times: %q", name, n, args)
		}
		// Kept from before: signed templates only for the own set, and no
		// update check at scan time.
		if !slices.Contains(args, "-disable-update-check") {
			t.Errorf("%s: missing -disable-update-check: %q", name, args)
		}
	}
}

// The DAST preset no longer selects default-login templates (they would be
// excluded anyway; selecting them only hid that).
func TestDASTPresetSelectsNoIntrusiveTag(t *testing.T) {
	for _, tag := range NewDAST().Tags {
		if slices.Contains(T1ExcludedTags, tag) {
			t.Errorf("NewDAST selects intrusive tag %q", tag)
		}
	}
	if slices.Contains(NewDAST().Capabilities(), "default_credentials") {
		t.Error("NewDAST still advertises default_credentials")
	}
}

// SECURITY (negative): a scan that asks for an intrusive template class is
// refused with a reason, not run with the tag silently filtered.
func TestScanRefusesIntrusiveTags(t *testing.T) {
	for _, tag := range []string{"default-login", "bruteforce", "brute-force", "intrusive", "dos", "fuzz", "fuzzing"} {
		_, err := NewScanner().forScan(&core.ScanOptions{Settings: scanSettings(t, map[string]any{"tags": []any{"cve", tag}})})
		if err == nil {
			t.Errorf("tag %q accepted", tag)
			continue
		}
		if !strings.Contains(err.Error(), tag) || !strings.Contains(err.Error(), "non-intrusive") {
			t.Errorf("tag %q: unhelpful refusal %q", tag, err)
		}
	}
	// Non-intrusive tags still work.
	if _, err := NewScanner().forScan(&core.ScanOptions{Settings: scanSettings(t, map[string]any{"tags": []any{"cve", "takeover", "exposure"}})}); err != nil {
		t.Errorf("non-intrusive tags refused: %v", err)
	}
}

// SECURITY (negative): a scan's exclude_tags only add; the tier exclusions
// stay.
func TestScanExcludeTagsCannotRemoveTierExclusions(t *testing.T) {
	got := argsWith(t, NewScanner(), map[string]any{"exclude_tags": []any{"wordpress"}})
	etags := strings.Split(settingFlag(got, "-etags"), ",")
	for _, want := range append(slices.Clone(T1ExcludedTags), "wordpress") {
		if !slices.Contains(etags, want) {
			t.Errorf("-etags %q lost %q", etags, want)
		}
	}
}

// SECURITY (negative): measured on nuclei v3.11.1, -itags re-admits a
// template -etags excluded. Extra args cannot carry it in any spelling.
func TestExtraArgsCannotReadmitExcludedTemplates(t *testing.T) {
	s := NewScanner()
	for _, extra := range [][]string{
		{"-itags", "default-login"},
		{"--itags", "intrusive"},
		{"-itags=default-login"},
		{"-include-tags", "dos"},
		{" -INCLUDE-TAGS=fuzz"},
		{"-it", "x.yaml"}, // the SDK's own list
	} {
		// Refused before nuclei runs (the binary is not even looked up).
		if _, err := s.Scan(t.Context(), "https://example.com", &core.ScanOptions{ExtraArgs: extra}); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("Scan with extra args %q: %v", extra, err)
		}
		if _, err := s.ScanTargets(t.Context(), []string{"https://example.com"}, &core.ScanOptions{ExtraArgs: extra}); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("ScanTargets with extra args %q: %v", extra, err)
		}
	}
	// A value that merely contains the word is not a flag.
	if err := checkTierExtraArgs([]string{"-severity", "itags"}); err != nil {
		t.Errorf("non-flag value refused: %v", err)
	}
}

// Re-verification excludes default-login templates too, and refuses an id
// of that class before running anything.
func TestValidateExcludesDefaultLogin(t *testing.T) {
	args, err := buildValidateArgs(ValidateOptions{Target: "https://example.com", TemplateID: "CVE-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(settingFlag(args, "-etags"), "default-login") {
		t.Errorf("validate -etags misses default-login: %q", args)
	}
	if _, err := buildValidateArgs(ValidateOptions{Target: "https://example.com", TemplateID: "tomcat-default-login"}); err == nil {
		t.Error("a default-login template id was accepted for re-verification")
	}
}
