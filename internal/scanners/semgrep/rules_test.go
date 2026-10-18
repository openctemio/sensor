package semgrep

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// rulesFile writes a local rules file for a test.
func rulesFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// SECURITY: only local rules run. A registry name, a URL or a flag is
// refused before semgrep starts, and a scan without rules fails instead of
// falling back to "--config auto": rules are never fetched from the rules
// registry on a tenant's behalf.
func TestRuleConfigs_LocalOnly(t *testing.T) {
	for _, c := range []string{"auto", "p/default", "r/python.lang.security", "https://semgrep.dev/c/p/default", "--config=x", " ", "no/such/rules.yaml"} {
		s := NewScanner()
		s.Configs = []string{c}
		if _, err := s.ruleConfigs(nil); err == nil {
			t.Errorf("rules %q accepted", c)
		}
		if _, err := s.ruleConfigs(&core.ScanOptions{ConfigFile: c}); err == nil {
			t.Errorf("config file %q accepted", c)
		}
		if _, err := NewScanner().ruleConfigs(&core.ScanOptions{CustomTemplateDir: c}); err == nil && strings.TrimSpace(c) != "" {
			t.Errorf("custom rules %q accepted", c)
		}
	}
	if _, err := NewScanner().ruleConfigs(nil); !errors.Is(err, ErrNoRules) {
		t.Fatalf("no rules: err = %v", err)
	}
	rules := rulesFile(t)
	custom := t.TempDir()
	s := NewScanner()
	s.Configs = []string{rules}
	got, err := s.ruleConfigs(&core.ScanOptions{CustomTemplateDir: custom})
	if err != nil || !slices.Equal(got, []string{custom, rules}) {
		t.Fatalf("configs = %v, %v", got, err)
	}
}

// The command line names only the resolved local rules, never "auto", and
// turns usage metrics off.
func TestBuildArgs_NoRegistry(t *testing.T) {
	args := NewScanner().buildArgs("/src", "/tmp/r/out.json", []string{"/rules"}, nil)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--config /rules") || strings.Contains(joined, "auto") {
		t.Fatalf("args %q", joined)
	}
	if !strings.Contains(joined, "--metrics off") {
		t.Fatalf("metrics not off: %q", joined)
	}
}
