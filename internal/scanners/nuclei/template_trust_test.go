package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func writeTemplates(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const httpTemplate = "id: probe\ninfo:\n  name: probe\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n"

func TestCheckCustomTemplates(t *testing.T) {
	if err := CheckCustomTemplates(writeTemplates(t, map[string]string{"ok.yaml": httpTemplate})); err != nil {
		t.Fatalf("an http template was refused: %v", err)
	}
	refused := map[string]string{
		"code":            "id: x\ninfo: {name: x, severity: info}\ncode:\n  - engine: [sh]\n    source: id\n",
		"code upper-case": "id: x\ninfo: {name: x, severity: info}\nCODE:\n  - engine: [sh]\n    source: id\n",
		"code flow-style": `{"id": "x", "info": {"name": "x", "severity": "info"}, "code": [{"engine": ["sh"], "source": "id"}]}`,
		"javascript":      "id: x\ninfo: {name: x, severity: info}\njavascript:\n  - code: 'require(\"nuclei/fs\")'\n",
		"file":            "id: x\ninfo: {name: x, severity: info}\nfile:\n  - extensions: [all]\n",
		"headless":        "id: x\ninfo: {name: x, severity: info}\nheadless:\n  - steps: [{action: script, args: {code: 'alert(1)'}}]\n",
		"self-contained":  "id: x\ninfo: {name: x, severity: info}\nself-contained: true\nhttp: []\n",
		"not yaml":        "id: [unclosed\n",
	}
	for name, body := range refused {
		t.Run(name, func(t *testing.T) {
			if err := CheckCustomTemplates(writeTemplates(t, map[string]string{"t.yaml": body})); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// fakeRecordingNuclei records each run's arguments (one line per run) and
// prints one result per run.
func fakeRecordingNuclei(t *testing.T) (bin, record string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "nuclei")
	record = filepath.Join(dir, "runs")
	script := `#!/bin/sh
echo "$*" >> "` + record + `"
printf '{"template-id":"run","info":{"name":"t","severity":"info"},"host":"h","matched-at":"h"}\n'
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, record
}

func readRuns(t *testing.T, record string) []string {
	t.Helper()
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// A scan with custom templates runs the sensor's own set with signatures
// enforced, then the custom templates alone with code, file, headless and
// javascript excluded; both runs' results come back.
func TestScanWithCustomTemplatesKeepsSignatureCheck(t *testing.T) {
	bin, record := fakeRecordingNuclei(t)
	s := NewScanner()
	s.Binary = bin
	s.TemplateDir = "/content/nuclei-templates/current"
	s.Headless = true
	dir := writeTemplates(t, map[string]string{"probe.yaml": httpTemplate})

	res, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{CustomTemplateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	runs := readRuns(t, record)
	if len(runs) != 2 {
		t.Fatalf("runs = %q, want 2", runs)
	}
	own, custom := strings.Fields(runs[0]), strings.Fields(runs[1])
	if !slices.Contains(own, "-disable-unsigned-templates") || slices.Contains(own, dir) || !slices.Contains(own, s.TemplateDir) {
		t.Errorf("own run %v: want the managed set with -disable-unsigned-templates and no custom templates", own)
	}
	i := slices.Index(custom, "-exclude-type")
	if i < 0 || custom[i+1] != "code,file,headless,javascript" {
		t.Errorf("custom run %v: want -exclude-type code,file,headless,javascript", custom)
	}
	if !slices.Contains(custom, dir) || slices.Contains(custom, s.TemplateDir) || slices.Contains(custom, "-headless") {
		t.Errorf("custom run %v: want only the custom templates, no headless", custom)
	}
	if got := strings.Count(string(res.RawOutput), "\n"); got != 2 {
		t.Errorf("output has %d results, want both runs' (2): %q", got, res.RawOutput)
	}
}

// A custom template that uses the code protocol never reaches nuclei, even
// though the SDK accepted its signature.
func TestScanRefusesCodeProtocolCustomTemplate(t *testing.T) {
	bin, record := fakeRecordingNuclei(t)
	s := NewScanner()
	s.Binary = bin
	dir := writeTemplates(t, map[string]string{"rce.yaml": "id: rce\ninfo: {name: rce, severity: info}\ncode:\n  - engine: [sh]\n    source: id\n"})
	if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{CustomTemplateDir: dir}); err == nil {
		t.Fatal("a code-protocol custom template was run")
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("nuclei was started")
	}
	if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{ExtraArgs: []string{"-code"}}); err == nil {
		t.Fatal("-code in extra args was accepted")
	}
}
