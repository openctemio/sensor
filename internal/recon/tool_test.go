package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
	"github.com/openctemio/sensor/internal/toolrun"
)

func TestMain(m *testing.M) {
	// This test binary is also the tool child of the out-of-process path.
	executor.RunLauncherIfRequested()
	adapter.Dispatch(toolrun.Registered()...)
	os.Exit(m.Run())
}

// fakeHTTPX prints the recorded real httpx output for every target, and
// fails on bad.example as httpx does when a target cannot be read.
func fakeHTTPX(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(flagcheck.Testdata("httpx-1.12.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out.jsonl")
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "httpx")
	script := "#!/bin/sh\ncase \"$*\" in *bad.example*) echo 'no valid input' >&2; exit 1;; esac\ncat " + out + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func httpxScanner(t *testing.T) *Scanner {
	s, err := New("httpx")
	if err != nil {
		t.Fatal(err)
	}
	hx := s.Recon().(*httpx.Scanner)
	hx.Binary = fakeHTTPX(t)
	hx.SetVersion("v1.12.0") // as IsInstalled found it
	return s
}

// The ported httpx gives the same CTIS out of process (in the task sandbox,
// through the runtime's checks) as the direct path.
func TestHTTPXOutOfProcessParity(t *testing.T) {
	targets := []string{"https://example.com", "https://bad.example"}
	t.Setenv(toolrun.EnvRuntime, "in-process")
	direct, err := httpxScanner(t).ScanTargets(context.Background(), targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	oop, err := httpxScanner(t).ScanTargets(context.Background(), targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := toolrun.NormalizeForParity(direct.RawOutput)
	if err != nil {
		t.Fatal(err)
	}
	b, err := toolrun.NormalizeForParity(oop.RawOutput)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("out-of-process CTIS differs from the direct path\n--- direct\n%s\n--- out of process\n%s", a, b)
	}
	if !strings.Contains(string(a), "http_service") || !strings.Contains(string(a), "bad.example") {
		t.Fatalf("the corpus did not exercise assets and a failed target:\n%s", a)
	}
	var rep map[string]any
	_ = json.Unmarshal(oop.RawOutput, &rep)
	prov, _ := json.Marshal(rep["metadata"].(map[string]any)["properties"].(map[string]any)["provenance"])
	if !strings.Contains(string(prov), `"tool":"httpx"`) || !strings.Contains(string(prov), "built-in") {
		t.Fatalf("provenance %s", prov)
	}
	golden(t, filepath.Join("testdata", "httpx-tool-parity.golden.json"), b)
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

// A run that fails on every target fails the job on both paths.
func TestHTTPXOutOfProcessAllTargetsFail(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	_, err := httpxScanner(t).ScanTargets(context.Background(), []string{"https://bad.example"}, nil)
	if err == nil || !strings.Contains(err.Error(), "recon tool failed") {
		t.Fatalf("got %v", err)
	}
}
