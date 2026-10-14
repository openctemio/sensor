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
	src := &SemgrepRules{Binary: fakeSemgrep(t), Registry: srv.URL, Fetcher: &Fetcher{AllowHTTP: true, Trusted: true}}
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

// fakeOpengrep answers a check run as opengrep does: it refuses --metrics
// (exit 2) and needs a log directory (XDG_CONFIG_HOME).
func fakeOpengrep(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "opengrep")
	script := `#!/bin/sh
[ -d "$XDG_CONFIG_HOME" ] || { echo "no log dir" >&2; exit 2; }
cfg=""
while [ $# -gt 0 ]; do
  case "$1" in --metrics*) echo "opengrep scan: unknown option --metrics" >&2; exit 2;; esac
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

// With opengrep as the engine, a rules bundle is checked by opengrep
// (without the --metrics flag it refuses), reported under opengrep, and
// without a bundle the content says opengrep has no rules (it never
// fetches any per scan).
func TestOpengrepEngineRules(t *testing.T) {
	m := newTestManager(t, &SemgrepRules{Engine: EngineOpengrep, Fetcher: &Fetcher{}})
	if res := m.Refresh(context.Background(), nil, true); !res[0].Skipped {
		t.Fatalf("%+v", res)
	}
	rep := m.Report(EngineOpengrep)
	if len(rep) != 1 || rep[0].Managed || !strings.Contains(rep[0].Source, "local rules only") {
		t.Fatalf("unmanaged report %+v", rep)
	}

	path := filepath.Join(t.TempDir(), "rules.yaml")
	_ = os.WriteFile(path, []byte(goodRules), 0o644)
	src := &SemgrepRules{Engine: EngineOpengrep, Binary: fakeOpengrep(t), LocalPath: path, Fetcher: &Fetcher{}}
	m = newTestManager(t, src)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
	h := m.Acquire(core.ContentSemgrepRules)
	if h == nil || !strings.Contains(strings.Join(h.Meta.Checks, ","), "opengrep-load") {
		t.Fatalf("checks %+v", h)
	}
	h.Release()
	_ = os.WriteFile(path, []byte(goodRules+"# BROKEN\n"), 0o644)
	if res := m.Refresh(context.Background(), nil, false); res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "opengrep") {
		t.Fatalf("rules opengrep rejects installed: %+v", res)
	}
}

func TestNewFromSettings_OpengrepEngine(t *testing.T) {
	m, err := NewFromSettings(Settings{Enabled: true, Root: t.TempDir()}, Tools{Semgrep: true, Opengrep: true}, false)
	if err != nil || m == nil {
		t.Fatalf("%v %v", m, err)
	}
	if rep := m.Report(EngineOpengrep); len(rep) != 1 || rep[0].Name != core.ContentSemgrepRules {
		t.Fatalf("one rules bundle, checked by opengrep: %+v", rep)
	}
}
