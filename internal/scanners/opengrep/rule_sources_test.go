package opengrep

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"

	"github.com/openctemio/sensor/internal/toolrun"
)

// The job's rule sources pick the configs: the organization's rules, the
// platform's, or both in one run.
func TestRuleConfigsHonorRuleSources(t *testing.T) {
	rules := rulesFile(t)
	custom := t.TempDir()
	s := NewScanner()
	s.Configs = []string{rules}
	for _, c := range []struct {
		rs     core.RuleSources
		custom string
		want   []string
	}{
		{core.RuleSourcesBoth, custom, []string{custom, rules}},
		{core.RuleSourcesTenant, custom, []string{custom}},
		{core.RuleSourcesPlatform, "", []string{rules}},
	} {
		got, err := s.ruleConfigs(&core.ScanOptions{CustomTemplateDir: c.custom, RuleSources: c.rs})
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: configs = %v, %v; want %v", c.rs, got, err, c.want)
		}
	}
	if _, err := s.ruleConfigs(&core.ScanOptions{CustomTemplateDir: custom, RuleSources: core.RuleSourcesPlatform}); err == nil {
		t.Error("platform-only with custom rules accepted")
	}
	if _, err := s.ruleConfigs(&core.ScanOptions{RuleSources: core.RuleSourcesTenant}); err == nil {
		t.Error("tenant-only without custom rules accepted (it would run the platform's rules)")
	}
}

// One opengrep run with the platform's and the organization's rules: the
// organization's rule reports as tenant:<id>, the platform's keeps its id
// even when both use the same id.
func TestOrganizationRuleIDsComeBackPrefixed(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "opengrep")
	// Report every rule id of every --config file: rewritten ids as they are.
	script := `#!/bin/sh
out=""; prev=""; ids=""
for a in "$@"; do
  [ "$prev" = "--output" ] && out="$a"
  if [ "$prev" = "--config" ]; then
    for f in "$a" "$a"/*; do
      [ -f "$f" ] && ids="$ids $(sed -n 's/^ *- id: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' "$f")"
    done
  fi
  prev="$a"
done
printf '{"results":[' > "$out"; sep=""
for id in $ids; do printf '%s{"check_id":"%s","path":"a.py","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR"}}' "$sep" "$id" >> "$out"; sep=","; done
printf '],"errors":[]}' >> "$out"
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	platform := filepath.Join(t.TempDir(), "platform.yaml")
	if err := os.WriteFile(platform, []byte("rules:\n  - id: weak-hash\n    pattern: md5(...)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	custom := t.TempDir()
	if err := os.WriteFile(filepath.Join(custom, "mine.yaml"), []byte("rules:\n  - id: weak-hash\n    pattern: sha1(...)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	s := NewScanner()
	s.Binary = bin
	s.Configs = []string{platform}
	res, err := s.scanDirect(context.Background(), t.TempDir(), &core.ScanOptions{CustomTemplateDir: custom, RuleSources: core.RuleSourcesBoth})
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Results []struct {
			CheckID string `json:"check_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(res.RawOutput, &rep); err != nil {
		t.Fatalf("%v: %s", err, res.RawOutput)
	}
	var ids []string
	for _, r := range rep.Results {
		ids = append(ids, r.CheckID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"tenant:weak-hash", "weak-hash"}) {
		t.Fatalf("rule ids = %v, want the organization's prefixed and the platform's as is", ids)
	}
	if b, _ := os.ReadFile(filepath.Join(custom, "mine.yaml")); !strings.Contains(string(b), "id: weak-hash") {
		t.Fatal("the received rules were changed")
	}
}
