package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/toolrun"
)

// provenanceOf is the runtime's provenance of a scan result.
func provenanceOf(t *testing.T, raw []byte) string {
	t.Helper()
	var rep map[string]any
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	md, _ := rep["metadata"].(map[string]any)
	props, _ := md["properties"].(map[string]any)
	b, _ := json.Marshal(props["provenance"])
	return string(b)
}

// Every recon tool, run as a capability job on the real converter output
// of its corpus, meets the contract of the capability it implements: no
// output outside the capability, every required CTIS path present.
func TestReconOutputMeetsItsCapabilityContract(t *testing.T) {
	withSensorResolver(t)
	cases := []struct {
		capability string
		mk         func(*testing.T) *Scanner
		targets    []string
	}{
		{"discover.subdomains@1", subfinderScanner, []string{"example.com"}},
		{"resolve.dns@1", dnsxScanner, []string{"example.com"}},
		{"scan.ports@1", naabuScanner, []string{"127.0.0.1"}},
		{"probe.http@1", httpxScanner, []string{"127.0.0.1"}},
		{"crawl.web@1", katanaScanner, []string{"http://127.0.0.1:18777"}},
	}
	for _, tc := range cases {
		t.Run(tc.capability, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, "")
			s := tc.mk(t)
			if !s.TakesCapabilityJobs() {
				t.Fatal("a recon tool on the contract must take capability jobs")
			}
			res, err := s.ScanTargets(context.Background(), tc.targets, &core.ScanOptions{Capability: tc.capability, MaxTier: "T1"})
			if err != nil {
				t.Fatal(err)
			}
			prov := provenanceOf(t, res.RawOutput)
			if !strings.Contains(prov, `"capability":"`+tc.capability+`"`) {
				t.Fatalf("the capability did not reach the runtime: %s", prov)
			}
			if strings.Contains(prov, "contract_violations") {
				t.Fatalf("the output misses the %s contract: %s", tc.capability, prov)
			}
		})
	}
}

// The workflow's standard params reach naabu as its own flags, through the
// descriptor's mapping, together with the scan's own settings.
func TestNaabuCapabilityParamsReachTheChild(t *testing.T) {
	withSensorResolver(t)
	t.Setenv(toolrun.EnvRuntime, "")
	s := naabuScanner(t)
	nb := s.Recon().(*naabu.Scanner)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(out, testdata(t, "naabu-2.6.1.jsonl"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nfor want in '-p 8080,8443' '-rate 7' '-retries 0'; do\n" +
		"  case \"$*\" in *\"$want\"*) ;; *) echo \"missing $want in $*\" >&2; exit 4;; esac\ndone\ncat " + out + "\n"
	nb.Binary = filepath.Join(dir, "naabu")
	if err := os.WriteFile(nb.Binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ts, err := nb.SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"retries": 0}})
	if err != nil {
		t.Fatal(err)
	}
	opts := &core.ScanOptions{Settings: ts, Capability: "scan.ports@1",
		Params: map[string]json.RawMessage{"ports": json.RawMessage(`"8080,8443"`), "rate": json.RawMessage(`7`)}}
	res, err := s.ScanTargets(context.Background(), []string{"127.0.0.1"}, opts)
	if err != nil {
		t.Fatalf("the params did not reach the child: %v", err)
	}
	if !strings.Contains(provenanceOf(t, res.RawOutput), `"capability":"scan.ports@1"`) {
		t.Fatal("no capability in the provenance")
	}
	if opts.Settings != ts {
		t.Fatal("the caller's options were modified")
	}
}

// SECURITY: a capability job never runs with a setting the tool cannot
// honor, above the job's tier, or with a param that contradicts the scan.
func TestReconCapabilityJobRefusals(t *testing.T) {
	withSensorResolver(t)
	ts, _ := naabu.NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"ports": "80"}})
	cases := map[string]struct {
		opts *core.ScanOptions
		want string
	}{
		"param the tool does not take": {&core.ScanOptions{Capability: "scan.ports@1", Params: map[string]json.RawMessage{"protocol": json.RawMessage(`"tcp"`)}}, "does not take"},
		"value outside the capability": {&core.ScanOptions{Capability: "scan.ports@1", Params: map[string]json.RawMessage{"rate": json.RawMessage(`0`)}}, "below the minimum"},
		"tier above the ceiling":       {&core.ScanOptions{Capability: "scan.ports@1", MaxTier: "T0"}, "allows at most T0"},
		"another capability":           {&core.ScanOptions{Capability: "probe.http@1"}, "does not implement"},
		"param contradicts the scan": {&core.ScanOptions{Settings: ts, Capability: "scan.ports@1",
			Params: map[string]json.RawMessage{"ports": json.RawMessage(`"443"`)}}, "another value"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := naabuScanner(t).ScanTargets(context.Background(), []string{"127.0.0.1"}, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
