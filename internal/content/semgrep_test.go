package content

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

const goodRules = "rules:\n- id: no-eval\n  pattern: eval(...)\n  message: m\n  languages: [python]\n  severity: ERROR\n"

// fakeSemgrep answers a check run: errors when a rules file contains BROKEN.
func fakeSemgrep(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := `#!/bin/sh
cfg=""
while [ $# -gt 0 ]; do
  [ "$1" = "--config" ] && cfg="$2"
  shift
done
if grep -rq BROKEN "$cfg"; then echo '{"errors":[{"message":"bad rule"}],"results":[]}'; exit 2; fi
echo '{"errors":[],"results":[]}'
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	return bin
}

func TestSemgrepUnmanagedByDefault(t *testing.T) {
	m := newTestManager(t, &SemgrepRules{Fetcher: &Fetcher{}})
	if res := m.Refresh(context.Background(), nil, true); !res[0].Skipped {
		t.Fatalf("%+v", res)
	}
	rep := m.Report("semgrep")
	if len(rep) != 1 || rep[0].Managed || rep[0].Name != core.ContentSemgrepRules || !strings.Contains(rep[0].Source, "auto") {
		t.Fatalf("report %+v", rep)
	}
}

func TestSemgrepRulesetsFromPolicy(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		_, _ = w.Write([]byte(goodRules))
	}))
	defer srv.Close()
	src := &SemgrepRules{Binary: fakeSemgrep(t), Registry: srv.URL, Fetcher: &Fetcher{AllowHTTP: true}}
	m := newTestManager(t, src)
	if err := m.SetPolicy(core.ContentPolicy{Content: map[string]core.ContentPin{
		core.ContentSemgrepRules: {Rulesets: []string{"p/default", "p/owasp-top-ten"}},
	}}); err != nil {
		t.Fatal(err)
	}
	res := m.Refresh(context.Background(), nil, false)
	if res[0].Err != nil || !res[0].Refreshed {
		t.Fatalf("%+v", res)
	}
	if strings.Join(asked, ",") != "/c/p/default,/c/p/owasp-top-ten" {
		t.Fatalf("asked %v", asked)
	}
	h := m.Acquire(core.ContentSemgrepRules)
	defer h.Release()
	if !strings.HasPrefix(h.Meta.Version, "sha256:") || len(h.Meta.Version) != 19 {
		t.Fatalf("version %q", h.Meta.Version)
	}
	// Same rules again: unchanged, nothing swapped.
	if res = m.Refresh(context.Background(), nil, false); !res[0].Unchanged {
		t.Fatalf("%+v", res)
	}
}

func TestSemgrepLocalRulesAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	_ = os.WriteFile(path, []byte(goodRules), 0o644)
	src := &SemgrepRules{Binary: fakeSemgrep(t), LocalPath: path, Fetcher: &Fetcher{}}
	m := newTestManager(t, src)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err != nil {
		t.Fatalf("%+v", res)
	}

	// Rules semgrep rejects never become current.
	_ = os.WriteFile(path, []byte(goodRules+"# BROKEN\n"), 0o644)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil {
		t.Fatal("rejected rules installed")
	}
	// Rules without ids fail the Go-level check.
	_ = os.WriteFile(path, []byte("rules:\n- pattern: x\n"), 0o644)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "no id") {
		t.Fatalf("%+v", res)
	}
	_ = os.WriteFile(path, []byte("not: rules\n"), 0o644)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil {
		t.Fatal("non-rules file installed")
	}
}

func TestSemgrepRulesetValidated(t *testing.T) {
	src := &SemgrepRules{Fetcher: &Fetcher{}}
	if _, err := src.Resolve(context.Background(), core.ContentPin{Rulesets: []string{"../../etc"}}); err == nil {
		t.Fatal("traversal ruleset accepted")
	}
}
