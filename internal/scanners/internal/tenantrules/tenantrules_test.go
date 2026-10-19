package tenantrules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

const ruleFile = `rules:
  - id: hardcoded-password
    languages: [python]
    severity: ERROR
    message: m
    pattern: password = "..."
  - id: weak-hash
    languages: [python]
    severity: WARNING
    message: m
    pattern: md5(...)
`

func writeRules(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The organization's rule ids run under a per-run marker and come back in
// the report as tenant:<id>; a platform rule of the same id is untouched.
func TestPrepareAndRestore(t *testing.T) {
	src := writeRules(t, map[string]string{"mine.yaml": ruleFile})
	r, cleanup, err := PrepareSemgrep(src)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got, err := os.ReadFile(filepath.Join(r.Dir, "mine.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got), r.prefix) != 2 || strings.Contains(string(got), "tenant:") {
		t.Fatalf("rewritten rules:\n%s", got)
	}
	if orig, _ := os.ReadFile(filepath.Join(src, "mine.yaml")); string(orig) != ruleFile {
		t.Fatal("the received rules were changed")
	}
	report := `{"results":[{"check_id":"` + r.prefix + `hardcoded-password","path":"a.py"},{"check_id":"hardcoded-password","path":"b.py"}],"errors":[]}`
	var rep struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
		} `json:"results"`
	}
	if err := json.Unmarshal(r.RestoreReport([]byte(report)), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].CheckID != "tenant:hardcoded-password" || rep.Results[1].CheckID != "hardcoded-password" || rep.Results[0].Path != "a.py" {
		t.Fatalf("restored = %+v", rep.Results)
	}
	var none *Rules
	if string(none.RestoreReport([]byte(report))) != report {
		t.Fatal("nil rules changed a report")
	}
}

func TestPrepareRefusesMalformedRuleFiles(t *testing.T) {
	for name, body := range map[string]string{
		"not yaml":        "rules: [unclosed\n",
		"no rules":        "other: 1\n",
		"empty rules":     "rules: []\n",
		"rule without id": "rules:\n  - pattern: x\n",
		"id not string":   "rules:\n  - id: [a]\n",
		"two documents":   ruleFile + "---\nrules: []\n",
	} {
		if _, _, err := PrepareSemgrep(writeRules(t, map[string]string{"r.yaml": body})); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSelectHonorsRuleSources(t *testing.T) {
	platform := []string{"/content/rules"}
	cases := []struct {
		rs     core.RuleSources
		custom string
		want   []string
		err    error
	}{
		{"", "/c", []string{"/c", "/content/rules"}, nil},
		{core.RuleSourcesBoth, "", []string{"/content/rules"}, nil},
		{core.RuleSourcesTenant, "/c", []string{"/c"}, nil},
		{core.RuleSourcesPlatform, "", []string{"/content/rules"}, nil},
		{core.RuleSourcesPlatform, "/c", nil, ErrPlatformWithCustom},
		{core.RuleSourcesTenant, "", nil, ErrTenantWithoutRules},
	}
	for _, c := range cases {
		got, err := Select(&core.ScanOptions{RuleSources: c.rs}, c.custom, platform)
		if !errors.Is(err, c.err) || !slices.Equal(got, c.want) {
			t.Errorf("Select(%q, %q) = %v, %v; want %v, %v", c.rs, c.custom, got, err, c.want, c.err)
		}
	}
}
