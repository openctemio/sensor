package nuclei

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Variants of the nuclei tool with tighter manifests, to show the runtime
// enforcing them on the real run function.
var (
	limitedTool = tool.New(variant("nuclei-limited", func(m *tool.Manifest) { m.Resources.MaxRecords = 5 }), runTool)
	narrowTool  = tool.New(variant("nuclei-narrow", func(m *tool.Manifest) {
		m.Produces = []string{"asset:domain", "asset:ip_address", "asset:service", "finding:vulnerability"}
	}), runTool)
)

func variant(name string, f func(*tool.Manifest)) tool.Manifest {
	m := ToolManifest
	m.Name = name
	m.Produces = append([]string(nil), ToolManifest.Produces...)
	f(&m)
	return m
}

func TestMain(m *testing.M) {
	// This test binary is also the tool child of the out-of-process path.
	executor.RunLauncherIfRequested()
	adapter.Dispatch(Tool, ValidateTool, limitedTool, narrowTool)
	// The other tests of this package exercise the direct path.
	_ = os.Setenv(toolrun.EnvRuntime, "in-process")
	os.Exit(m.Run())
}

// fakeNuclei prints n results per target (-u or each line of -l): even
// ones are CVEs, odd ones misconfigurations; it records its arguments.
func fakeToolNuclei(t *testing.T, n int) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "nuclei")
	argsFile = filepath.Join(dir, "args")
	script := `#!/bin/sh
echo "$@" > "` + argsFile + `"
targets=""
while [ $# -gt 0 ]; do
  case "$1" in
    -u) targets="$2";;
    -l) targets="$(cat "$2")";;
  esac
  shift
done
for t in $targets; do
  i=0
  while [ $i -lt ` + itoa(n) + ` ]; do
    if [ $((i % 2)) -eq 0 ]; then tags='["cve"]'; else tags='["misconfig"]'; fi
    printf '{"template-id":"tpl-%d","info":{"name":"Template %d","severity":"high","tags":%s,"description":"d"},"host":"%s","matched-at":"%s/x","type":"http","ip":"203.0.113.9"}\n' $i $i "$tags" "$t" "$t"
    i=$((i+1))
  done
done
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func scanner(bin string) *Scanner {
	s := NewScanner()
	s.Binary = bin
	return s
}

func parse(t *testing.T, raw []byte) []byte {
	t.Helper()
	r, err := (&ReportParser{}).Parse(context.Background(), raw, &core.ParseOptions{ToolName: "nuclei"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b, err := toolrun.NormalizeReport(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The ported nuclei gives the same CTIS out of process (in the task
// sandbox, through the runtime's checks) as the direct path, for one
// target and for a list.
func TestOutOfProcessParity(t *testing.T) {
	bin, _ := fakeToolNuclei(t, 4)
	for _, targets := range [][]string{{"http://203.0.113.10"}, {"http://203.0.113.10", "http://203.0.113.11:8080"}} {
		run := func() *core.ScanResult {
			var res *core.ScanResult
			var err error
			if len(targets) == 1 {
				res, err = scanner(bin).Scan(context.Background(), targets[0], nil)
			} else {
				res, err = scanner(bin).ScanTargets(context.Background(), targets, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
		t.Setenv(toolrun.EnvRuntime, "in-process")
		direct := run()
		t.Setenv(toolrun.EnvRuntime, "")
		oop := run()
		if !isToolReport(oop.RawOutput) || isToolReport(direct.RawOutput) {
			t.Fatal("the out-of-process path did not run")
		}
		a, b := parse(t, direct.RawOutput), parse(t, oop.RawOutput)
		if string(a) != string(b) {
			t.Fatalf("out-of-process CTIS differs from the direct path\n--- direct\n%s\n--- out of process\n%s", a, b)
		}
		if len(targets) == 2 {
			golden(t, filepath.Join("testdata", "nuclei-tool-parity.golden.json"), b)
		}
	}
}

// The interactsh token reaches nuclei as a declared credential, never in
// the task's configuration, and never in what the runtime keeps.
func TestCredentialsReachTheToolOnly(t *testing.T) {
	bin, argsFile := fakeToolNuclei(t, 1)
	s := scanner(bin)
	s.InteractshServer, s.InteractshToken = "https://oast.example", "itok-secret-123456"
	t.Setenv(toolrun.EnvRuntime, "")
	res, err := s.Scan(context.Background(), "http://203.0.113.10", nil)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "itok-secret-123456") {
		t.Fatalf("token not delivered to nuclei: %s", args)
	}
	if strings.Contains(string(res.RawOutput), "itok-secret") || strings.Contains(res.Stderr, "itok-secret") {
		t.Fatal("token leaked into the report or stderr")
	}
	if s.InteractshToken != "itok-secret-123456" {
		t.Fatal("the scanner was modified")
	}
}

// SECURITY (acceptance): undeclared output is quarantined and a task over
// its record limit is stopped with a reason.
func TestManifestEnforcedOnTheRealTool(t *testing.T) {
	bin, _ := fakeToolNuclei(t, 10)
	sc := scanner(bin)
	local := nucleiLocal{Scanner: sc}
	targets := []string{"http://203.0.113.10"}

	_, out, err := toolrun.Run(context.Background(), narrowTool, targets, local, toolhost.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusPartial || out.Stats.Quarantined["finding:misconfiguration"] != 5 || len(out.Report.Findings) != 5 {
		t.Fatalf("narrow: %s %+v findings %d", out.Status, out.Stats, len(out.Report.Findings))
	}

	res, out, err := toolrun.Run(context.Background(), limitedTool, targets, local, toolhost.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusPartial || out.Err == nil || out.Err.Class != tool.ResourceExhausted || out.Stats.Records != 5 || res == nil {
		t.Fatalf("limited: %s %v %+v", out.Status, out.Err, out.Stats)
	}
}

// golden compares got with the file (OPENCTEM_UPDATE_GOLDEN=1 rewrites it).
func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if os.Getenv("OPENCTEM_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (OPENCTEM_UPDATE_GOLDEN=1 writes it)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("CTIS differs from %s\n%s", path, got)
	}
}

// A scan that finds nothing has no output on both paths.
func TestOutOfProcessNothingFound(t *testing.T) {
	bin, _ := fakeToolNuclei(t, 0)
	t.Setenv(toolrun.EnvRuntime, "")
	res, err := scanner(bin).Scan(context.Background(), "http://203.0.113.10", nil)
	if err != nil || len(res.RawOutput) != 0 {
		t.Fatalf("raw %q err %v", res.RawOutput, err)
	}
}
