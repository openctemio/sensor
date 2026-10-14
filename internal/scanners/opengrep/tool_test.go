package opengrep

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/scanners/importparse"
	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
	"github.com/openctemio/sensor/internal/toolrun"
)

const testRules = "rules:\n- id: example.python.weak-hash\n  languages: [python]\n  severity: WARNING\n  message: MD5 is a weak hash.\n  pattern: hashlib.md5(...)\n"

func rulesFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scanWith(t *testing.T, mode, bin, target, rules string) *core.ScanResult {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, mode)
	s := NewScanner()
	s.Binary = bin
	s.Configs = []string{rules}
	s.SetVersion("1.30.2")
	res, err := s.Scan(context.Background(), target, &core.ScanOptions{Exclude: []string{"vendor"}})
	if err != nil {
		t.Fatalf("%q: %v", mode, err)
	}
	return res
}

// opengrep out of process returns the same report as the direct path (the
// report lands outside the scanned tree and is removed), and the sensor's
// opengrep parser reads it under the opengrep tool name.
func TestOpengrepOutOfProcessParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "opengrep.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := reporttest.ReadOnlyTarget(t)
	rules := rulesFile(t)
	bin, log := reporttest.FakeTool(t, string(data))
	direct := scanWith(t, "in-process", bin, target, rules)
	oop := scanWith(t, "", bin, target, rules)
	reporttest.AssertOutsideAndRemoved(t, log, target)
	if string(direct.RawOutput) != string(oop.RawOutput) || oop.ScannerVersion != "1.30.2" || oop.ScannerName != "opengrep" {
		t.Fatalf("results differ: direct %d bytes, out of process %d bytes version %q name %q",
			len(direct.RawOutput), len(oop.RawOutput), oop.ScannerVersion, oop.ScannerName)
	}
	opts := &core.ParseOptions{ToolName: "opengrep", AssetType: "repository", AssetValue: "github.com/acme/app", Branch: "main"}
	rep, err := importparse.Opengrep().Parse(context.Background(), oop.RawOutput, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tool == nil || rep.Tool.Name != "opengrep" || len(rep.Findings) == 0 {
		t.Fatalf("report tool %+v, %d findings", rep.Tool, len(rep.Findings))
	}
	if rep.Findings[0].PartialFingerprints["matchBasedId/v1"] == "" {
		t.Error("opengrep's match-based id is not kept")
	}
}

// An opengrep failure (exit 2) fails the scan out of process as on the
// direct path.
func TestOpengrepFailureOutOfProcess(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "opengrep")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'invalid rule' >&2\nexit 2\n"), 0o700); err != nil { //nolint:gosec // test script must be executable
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	s := NewScanner()
	s.Binary = bin
	s.Configs = []string{rulesFile(t)}
	if _, err := s.Scan(context.Background(), dir, nil); err == nil {
		t.Fatal("a failed opengrep run succeeded")
	}
}

// SECURITY: opengrep has no network. Registry rules and any call out fail
// closed in the sandbox, not only in ruleConfigs.
func TestOpengrepManifest(t *testing.T) {
	if err := ToolManifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if ToolManifest.Permissions.Network != tool.NetNone {
		t.Fatalf("network = %q, want none", ToolManifest.Permissions.Network)
	}
	if c := NewScanner().ToolContract(); c == nil || c.Digest != ToolManifest.Contract().Digest {
		t.Fatalf("tool contract %+v", c)
	}
}

// SECURITY: only local rules run. A registry name, a URL or a flag is
// refused before opengrep starts, so rules are never fetched on a
// tenant's behalf.
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

// The command line: local rules, no engine metrics flag (opengrep has
// none and refuses it), stable rule ids, the scan's settings.
func TestBuildArgs(t *testing.T) {
	s := NewScanner()
	s.TaintIntrafile, s.RuleTimeout, s.MaxTargetBytes, s.Jobs, s.MaxMemory = true, 30, 2000000, 2, 4096
	args := s.buildArgs("/src", "/tmp/r/out.json", []string{"/rules"}, &core.ScanOptions{Exclude: []string{"vendor"}})
	got := strings.Join(args, " ")
	want := "scan --json --output /tmp/r/out.json --no-rewrite-rule-ids --disable-version-check --disable-nosem --x-ignore-semgrepignore-files --dataflow-traces --taint-intrafile --config /rules --exclude node_modules --exclude build --exclude dist --exclude vendor --exclude .env --exclude .venv --exclude .tox --exclude *.min.js --exclude .npm --exclude .yarn --exclude test --exclude tests --exclude *_test.go --exclude vendor --timeout 30 --max-target-bytes 2000000 --jobs 2 --max-memory 4096 /src"
	if got != want {
		t.Fatalf("args\n got %s\nwant %s", got, want)
	}
	if strings.Contains(got, "--metrics") || strings.Contains(got, "--pro") {
		t.Fatal("flag opengrep does not accept")
	}
}

// With the real binary (when installed): a scan of a small tree with local
// rules gives the finding, and a registry name is refused before the run.
func TestOpengrepRealBinary(t *testing.T) {
	bin, err := exec.LookPath("opengrep")
	if err != nil {
		t.Skip("opengrep not installed")
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "app.py"), []byte("import hashlib\nhashlib.md5(b'x')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	s := NewScanner()
	s.Binary = bin
	s.NoGitIgnore = true
	s.Configs = []string{rulesFile(t)}
	res, err := s.Scan(context.Background(), src, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := importparse.Opengrep().Parse(context.Background(), res.RawOutput, &core.ParseOptions{ToolName: "opengrep", AssetType: "repository", AssetValue: "github.com/acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].RuleID != "example.python.weak-hash" {
		t.Fatalf("findings %+v", rep.Findings)
	}
	s.Configs = []string{"p/default"}
	if _, err := s.Scan(context.Background(), src, nil); err == nil {
		t.Fatal("registry rules ran")
	}
}
