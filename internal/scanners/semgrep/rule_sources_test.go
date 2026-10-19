package semgrep

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
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
