package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
	"github.com/openctemio/sensor/internal/recon/subfinder"
	"github.com/openctemio/sensor/internal/toolrun"
)

// fakeTool writes a shell script standing in for a recon binary: it prints
// out for every run, fails on bad.example as the real tools do on a target
// they cannot read, and fails unless the sensor's resolver (10.53.0.1, set
// by withSensorResolver) is on its command line when needsResolver.
func fakeTool(t *testing.T, name string, out []byte, needsResolver bool) string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "out")
	if err := os.WriteFile(data, out, 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$*\" in *bad.example*) echo 'no valid input' >&2; exit 1;; esac\n"
	if needsResolver {
		script += "case \"$*\" in *10.53.0.1*) ;; *) echo 'not the sensor resolver' >&2; exit 3;; esac\n"
	}
	script += "cat " + data + "\n"
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// withSensorResolver makes the sensor's resolvers 10.53.0.1 in this
// process only: a tool child that read them itself would get the host's.
func withSensorResolver(t *testing.T) {
	t.Helper()
	old := sensorResolvers
	t.Cleanup(func() { sensorResolvers = old })
	sensorResolvers = func(func(string) (string, bool)) ([]string, error) { return []string{"10.53.0.1"}, nil }
}

func subfinderScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New("subfinder")
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Join([]string{
		`{"host":"www.example.com","input":"example.com","source":"crtsh"}`,
		`{"host":"api.example.com","input":"example.com","source":"alienvault"}`,
		`{"host":"example.com","input":"example.com","source":"crtsh"}`,
	}, "\n") + "\n"
	sf := s.Recon().(*subfinder.Scanner)
	sf.Binary = fakeTool(t, "subfinder", []byte(out), true)
	sf.SetVersion("v2.16.0")
	return s
}

func dnsxScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New("dnsx")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(flagcheck.Testdata("dnsx-1.3.1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dx := s.Recon().(*dnsx.Scanner)
	dx.Binary = fakeTool(t, "dnsx", data, true)
	dx.SetVersion("v1.3.1")
	return s
}

// parity runs the same scan on the direct path and out of process and
// requires the same CTIS (provenance aside), stamped by the runtime.
func parity(t *testing.T, name string, mk func(*testing.T) *Scanner, targets []string) []byte {
	t.Helper()
	t.Setenv(toolrun.EnvRuntime, "in-process")
	direct, err := mk(t).ScanTargets(context.Background(), targets, nil)
	if err != nil {
		t.Fatalf("direct: %v", err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	oop, err := mk(t).ScanTargets(context.Background(), targets, nil)
	if err != nil {
		t.Fatalf("out of process: %v", err)
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
	var rep map[string]any
	_ = json.Unmarshal(oop.RawOutput, &rep)
	prov, _ := json.Marshal(rep["metadata"].(map[string]any)["properties"].(map[string]any)["provenance"])
	if !strings.Contains(string(prov), `"tool":"`+name+`"`) || !strings.Contains(string(prov), "built-in") {
		t.Fatalf("%s ran in process (provenance %s)", name, prov)
	}
	return b
}

// subfinder and dnsx give the same CTIS out of process as on the direct
// path, the child resolving through the sensor's resolvers.
func TestSubfinderOutOfProcessParity(t *testing.T) {
	withSensorResolver(t)
	b := parity(t, "subfinder", subfinderScanner, []string{"example.com", "bad.example"})
	if !strings.Contains(string(b), `"subdomain"`) || !strings.Contains(string(b), "bad.example") {
		t.Fatalf("the corpus did not exercise subdomains and a failed target:\n%s", b)
	}
	golden(t, filepath.Join("testdata", "subfinder-tool-parity.golden.json"), b)
}

func TestDNSXOutOfProcessParity(t *testing.T) {
	withSensorResolver(t)
	b := parity(t, "dnsx", dnsxScanner, []string{"example.com", "bad.example"})
	if !strings.Contains(string(b), `"domain"`) || !strings.Contains(string(b), "bad.example") {
		t.Fatalf("the corpus did not exercise records and a failed target:\n%s", b)
	}
	golden(t, filepath.Join("testdata", "dnsx-tool-parity.golden.json"), b)
}

// Host-bound extra arguments, settings for a tool without settings and a
// run that fails everywhere are refused out of process as on the direct
// path, before or by the child.
func TestReconPortRefusals(t *testing.T) {
	withSensorResolver(t)
	t.Setenv(toolrun.EnvRuntime, "")
	ctx := context.Background()
	if _, err := subfinderScanner(t).ScanTargets(ctx, []string{"example.com"}, &core.ScanOptions{ExtraArgs: []string{"-fr"}}); err == nil || !strings.Contains(err.Error(), "stay on the target's host") {
		t.Fatalf("host-bound extra arg: %v", err)
	}
	if _, err := dnsxScanner(t).ScanTargets(ctx, []string{"example.com"}, &core.ScanOptions{Settings: &core.ToolSettings{}}); err == nil || !strings.Contains(err.Error(), "takes no settings") {
		t.Fatalf("settings: %v", err)
	}
	if _, err := dnsxScanner(t).ScanTargets(ctx, []string{"bad.example"}, nil); err == nil || !strings.Contains(err.Error(), "recon tool failed") {
		t.Fatalf("all targets failed: %v", err)
	}
}

// Every ported recon tool has a valid manifest that names what the recon
// converter emits for it, and its scanner reports that manifest.
func TestReconPortManifests(t *testing.T) {
	want := map[string][]string{
		"httpx":     {"asset:http_service", "asset:certificate"},
		"subfinder": {"asset:domain", "asset:subdomain"},
		"dnsx":      {"asset:domain"},
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
		s, err := New(name)
		if err != nil {
			t.Fatal(err)
		}
		c := s.ToolContract()
		if c == nil || c.Digest != p.manifest.Contract().Digest {
			t.Fatalf("%s: tool contract %+v", name, c)
		}
	}
	// A test double that borrows a ported tool's name is not ported.
	if c := NewScanner(&fakeRecon{name: "dnsx", typ: core.ReconTypeDNS}).ToolContract(); c != nil {
		t.Fatalf("a double named dnsx reports %+v", c)
	}
}
