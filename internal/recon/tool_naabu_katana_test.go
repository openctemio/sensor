package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/toolrun"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(flagcheck.Testdata(name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func naabuScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New("naabu")
	if err != nil {
		t.Fatal(err)
	}
	nb := s.Recon().(*naabu.Scanner)
	nb.Binary = fakeTool(t, "naabu", testdata(t, "naabu-2.6.1.jsonl"), true)
	nb.SetVersion("v2.6.1")
	return s
}

func katanaScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New("katana")
	if err != nil {
		t.Fatal(err)
	}
	kt := s.Recon().(*katana.Scanner)
	kt.Binary = fakeTool(t, "katana", testdata(t, "katana-1.7.0.jsonl"), false)
	kt.SetVersion("v1.7.0")
	return s
}

func TestNaabuOutOfProcessParity(t *testing.T) {
	withSensorResolver(t)
	b := parity(t, "naabu", naabuScanner, []string{"127.0.0.1", "bad.example"})
	if !strings.Contains(string(b), `"ports"`) || !strings.Contains(string(b), "bad.example") {
		t.Fatalf("the corpus did not exercise ports and a failed target:\n%s", b)
	}
	golden(t, filepath.Join("testdata", "naabu-tool-parity.golden.json"), b)
}

func TestKatanaOutOfProcessParity(t *testing.T) {
	b := parity(t, "katana", katanaScanner, []string{"http://127.0.0.1:18777", "http://bad.example"})
	if !strings.Contains(string(b), `"discovered_url"`) || !strings.Contains(string(b), "bad.example") {
		t.Fatalf("the corpus did not exercise URLs and a failed target:\n%s", b)
	}
	golden(t, filepath.Join("testdata", "katana-tool-parity.golden.json"), b)
}

// A scan's naabu settings are applied by the sensor and reach the child
// whole, including the parts kept in unexported fields (the lowered rate,
// retries given as 0).
func TestNaabuSettingsReachTheChild(t *testing.T) {
	withSensorResolver(t)
	t.Setenv(toolrun.EnvRuntime, "")
	s := naabuScanner(t)
	nb := s.Recon().(*naabu.Scanner)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(out, testdata(t, "naabu-2.6.1.jsonl"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nfor want in '-p 8080' '-rate 7' '-retries 0' '10.53.0.1' '-s c'; do\n" +
		"  case \"$*\" in *\"$want\"*) ;; *) echo \"missing $want in $*\" >&2; exit 4;; esac\ndone\ncat " + out + "\n"
	nb.Binary = filepath.Join(dir, "naabu")
	if err := os.WriteFile(nb.Binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ts, err := nb.SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan,
		Values: map[string]any{"ports": "8080", "rate": 7, "retries": 0}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanTargets(context.Background(), []string{"127.0.0.1"}, &core.ScanOptions{Settings: ts})
	if err != nil {
		t.Fatalf("settings did not reach the child: %v", err)
	}
	if !strings.Contains(string(res.RawOutput), "provenance") {
		t.Fatal("naabu ran in process")
	}
}

// The encoded scanner keeps every field a scan's settings set.
func TestNaabuJSONRoundTrip(t *testing.T) {
	nb := naabu.NewScanner()
	ts, err := nb.SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan,
		Values: map[string]any{"rate": 9, "retries": 0}})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := nb.WithSettings(ts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	var back naabu.Scanner
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(&back)
	if string(raw) != string(again) || !strings.Contains(string(raw), `"ScanRate":9`) || !strings.Contains(string(raw), `"RetriesSet":true`) {
		t.Fatalf("round trip lost settings:\n%s\n%s", raw, again)
	}
}

// A SYN scan needs raw sockets, which the sandbox never grants: it stays on
// the direct path instead of failing in the child.
func TestNaabuSYNStaysDirect(t *testing.T) {
	withSensorResolver(t)
	t.Setenv(toolrun.EnvRuntime, "")
	s := naabuScanner(t)
	s.Recon().(*naabu.Scanner).ScanType = naabu.ScanTypeSYN
	res, err := s.ScanTargets(context.Background(), []string{"127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.RawOutput), "provenance") {
		t.Fatal("a SYN scan ran out of process")
	}
}

func TestNaabuKatanaManifests(t *testing.T) {
	want := map[string][]string{
		"naabu":  {"asset:ip_address", "asset:host"},
		"katana": {"asset:discovered_url", "endpoint"},
	}
	for name, produces := range want {
		p := ports[name]
		if p == nil {
			t.Fatalf("%s is not ported", name)
		}
		if err := p.manifest.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Join(p.manifest.Produces, ",") != strings.Join(produces, ",") {
			t.Fatalf("%s produces %v, want %v", name, p.manifest.Produces, produces)
		}
		if len(p.manifest.Permissions.LinuxCaps) != 0 {
			t.Fatalf("%s declares capabilities", name)
		}
	}
}
