package main

// End to end on the sensor: a scan command's config, as the platform sends
// it for a pipeline step, goes through the SDK's command executor and ends
// up as exactly the expected flags on the tool's command line (a fake tool
// records its arguments). An injection attempt fails the command before the
// tool runs.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// recordingTool writes a fake tool that records its arguments, one per
// line, and prints nothing (a scan that found nothing).
func recordingTool(t *testing.T, name string) (dir, argsFile string) {
	t.Helper()
	dir = t.TempDir()
	argsFile = filepath.Join(dir, "args")
	fakeTool(t, dir, name, `for a in "$@"; do printf '%s\n' "$a"; done > "`+argsFile+`"`+"\n")
	return dir, argsFile
}

func runScanCommand(t *testing.T, s core.Scanner, scanner, config string) error {
	t.Helper()
	e := core.NewDefaultCommandExecutor(nil)
	e.AddScanner(s)
	payload := `{"scanner":"` + scanner + `","target":"93.184.215.14","config":` + config + `}`
	if !json.Valid([]byte(payload)) {
		t.Fatalf("bad payload %s", payload)
	}
	_, err := e.Execute(context.Background(), &core.Command{ID: "c1", Type: "scan", Payload: json.RawMessage(payload)})
	return err
}

func recordedArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("tool did not run: %v", err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func argAfter(args []string, flag string) string {
	for i := range args[:len(args)-1] {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

// The E2E finding: a step with ports "80" ran naabu on the top 100 ports.
func TestStepConfig_NaabuPortsReachTheCommandLine(t *testing.T) {
	dir, argsFile := recordingTool(t, "naabu")
	s, err := getScanner(ScannerConfig{Name: "naabu", Enabled: true, Binary: filepath.Join(dir, "naabu")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := runScanCommand(t, s, "naabu", `{"ports":"80","retries":1,"rate":50000,"threads":40}`); err != nil {
		t.Fatalf("scan: %v", err)
	}
	args := recordedArgs(t, argsFile)
	if got := argAfter(args, "-p"); got != "80" {
		t.Errorf("-p = %q in %q", got, args)
	}
	for _, a := range args {
		if a == "-top-ports" {
			t.Errorf("default -top-ports passed with ports 80: %q", args)
		}
	}
	if got := argAfter(args, "-retries"); got != "1" {
		t.Errorf("-retries = %q", got)
	}
	if got := argAfter(args, "-rate"); got != "1000" {
		t.Errorf("-rate = %q: a scan raised the sensor's rate", got)
	}
}

func TestStepConfig_NucleiTagsReachTheCommandLine(t *testing.T) {
	dir, argsFile := recordingTool(t, "nuclei")
	s, err := getScanner(ScannerConfig{Name: "nuclei", Enabled: true, Binary: filepath.Join(dir, "nuclei")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := runScanCommand(t, s, "nuclei", `{"tags":["cve","exposure"],"severity":["high","critical"]}`); err != nil {
		t.Fatalf("scan: %v", err)
	}
	args := recordedArgs(t, argsFile)
	if got := argAfter(args, "-tags"); got != "cve,exposure" {
		t.Errorf("-tags = %q in %q", got, args)
	}
	if got := argAfter(args, "-severity"); got != "high,critical" {
		t.Errorf("-severity = %q in %q", got, args)
	}
}

// SECURITY: an injection attempt in a step's config fails the command and
// the tool never runs.
func TestStepConfig_InjectionIsRefused(t *testing.T) {
	cases := []struct{ tool, config string }{
		{"naabu", `{"ports":"80 -nmap-cli id"}`},
		{"naabu", `{"ports":"-"}`},
		{"naabu", `{"ports":"80\n-o\n/etc/cron.d/x"}`},
		{"naabu", `{"ports":"70000"}`},
		{"nuclei", `{"tags":["cve","-code"]}`},
		{"nuclei", `{"tags":["dos"]}`},
		{"nuclei", `{"severity":["critical","-headless"]}`},
	}
	for _, tc := range cases {
		dir, argsFile := recordingTool(t, tc.tool)
		s, err := getScanner(ScannerConfig{Name: tc.tool, Enabled: true, Binary: filepath.Join(dir, tc.tool)}, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := runScanCommand(t, s, tc.tool, tc.config); err == nil {
			t.Errorf("%s %s accepted", tc.tool, tc.config)
		}
		if _, err := os.Stat(argsFile); err == nil {
			t.Errorf("%s ran for refused config %s", tc.tool, tc.config)
		}
	}
}
