package nuclei

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// PRIVACY (research/292): every nuclei run excludes the templates that only
// harvest personal data, for every preset, pass and mode, and a scanner's own
// exclusions are added, never replacing them.
func TestEveryRunExcludesPersonalDataTemplates(t *testing.T) {
	managed := NewScanner()
	managed.TemplateDir = "/content/nuclei-templates/v10.4.9"
	custom := &core.ScanOptions{CustomTemplateDir: "/tmp/tenant-templates"}
	own := NewScanner()
	own.ExcludeIDs = []string{"tech-detect", "email-extractor", " "}

	runs := map[string][]string{
		"default scanner":       NewScanner().buildArgs("https://example.com", nil),
		"managed templates":     managed.buildArgs("https://example.com", &core.ScanOptions{}),
		"own pass with custom":  managed.buildArgsFor("https://example.com", "", custom, passOwn),
		"custom templates pass": managed.buildArgsFor("https://example.com", "", custom, passCustom),
		"list mode":             NewScanner().buildArgsFor("", "/tmp/list.txt", nil, passOwn),
		"dast preset":           NewDAST().buildArgs("https://example.com", nil),
		"takeover preset":       NewTakeoverScanner().buildArgs("https://example.com", nil),
		"own exclusions":        own.buildArgs("https://example.com", nil),
	}
	for name, args := range runs {
		if n := strings.Count(" "+strings.Join(args, " ")+" ", " -exclude-id "); n != 1 {
			t.Fatalf("%s: -exclude-id passed %d times: %q", name, n, args)
		}
		ids := strings.Split(settingFlag(args, "-exclude-id"), ",")
		for _, want := range []string{"email-extractor", "secrets-patterns-pii", "rdap-whois", "credit-card-number-detect"} {
			if !slices.Contains(ids, want) {
				t.Errorf("%s: -exclude-id %q does not exclude %q", name, ids, want)
			}
		}
		if slices.Contains(ids, "") {
			t.Errorf("%s: blank id in %q", name, ids)
		}
	}
	ids := strings.Split(settingFlag(runs["own exclusions"], "-exclude-id"), ",")
	if !slices.Contains(ids, "tech-detect") || strings.Count(strings.Join(ids, ","), "email-extractor") != 1 {
		t.Errorf("own exclusions not merged once: %q", ids)
	}
}

// On the real binary and template set (the sensor image; skipped where
// nuclei or its templates are not installed): the exclusion drops each
// harvester even when a scan names it by id or by file.
func TestPersonalDataTemplatesExcludedRealNuclei(t *testing.T) {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		t.Skip("nuclei not installed")
	}
	home, _ := os.UserHomeDir()
	dir := home + "/nuclei-templates"
	if _, err := os.Stat(dir + "/http/miscellaneous/email-extractor.yaml"); err != nil {
		t.Skip("nuclei-templates not installed")
	}
	s := NewScanner()
	eid := settingFlag(s.buildArgs("https://example.com", nil), "-exclude-id")
	list := func(extra ...string) string {
		args := append([]string{"-duc", "-tl", "-t", dir}, extra...)
		out, err := exec.Command(bin, args...).CombinedOutput() //nolint:gosec // test: fixed binary and args
		if err != nil {
			t.Fatalf("nuclei -tl: %v: %s", err, out)
		}
		return string(out)
	}
	byID := list("-id", strings.Join(PIIExcludedTemplateIDs, ","))
	for _, id := range []string{"email-extractor", "rdap-whois"} {
		if !strings.Contains(byID, id) {
			t.Fatalf("template set lacks %s: %s", id, byID)
		}
	}
	got := list("-id", strings.Join(PIIExcludedTemplateIDs, ","), "-exclude-id", eid)
	for _, id := range PIIExcludedTemplateIDs {
		if strings.Contains(got, id+".yaml") {
			t.Errorf("%s still listed with -exclude-id: %s", id, got)
		}
	}
}
