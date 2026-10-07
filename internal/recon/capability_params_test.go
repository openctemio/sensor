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
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/subfinder"
	"github.com/openctemio/sensor/internal/toolrun"
)

// checkingTool is a fake engine that fails unless every want is on its
// command line and no refuse is, then prints out.
func checkingTool(t *testing.T, name string, out []byte, want, refuse []string) string {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "out")
	if err := os.WriteFile(data, out, 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n"
	for _, w := range want {
		script += "case \"$*\" in *'" + w + "'*) ;; *) echo 'missing " + w + "' >&2; exit 4;; esac\n"
	}
	for _, r := range refuse {
		script += "case \"$*\" in *'" + r + "'*) echo 'unexpected " + r + "' >&2; exit 5;; esac\n"
	}
	script += "cat " + data + "\n"
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func params(kv ...string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = json.RawMessage(kv[i+1])
	}
	return out
}

// The workflow's standard params reach each recon engine as its own flags,
// in the tool child, through the descriptor's mapping.
func TestCapabilityParamsReachTheEngines(t *testing.T) {
	withSensorResolver(t)
	httpxOut, _ := os.ReadFile(filepath.Join("testdata", "httpx-1.12.0.jsonl"))
	dnsxOut, _ := os.ReadFile(filepath.Join("testdata", "dnsx-1.3.1.jsonl"))
	katanaOut, _ := os.ReadFile(filepath.Join("testdata", "katana-1.7.0.jsonl"))
	subOut := []byte(`{"host":"www.example.com","input":"example.com","source":"crtsh"}` + "\n" +
		`{"host":"api.example.com","input":"example.com","source":"crtsh"}` + "\n")
	cases := []struct {
		tool, capability string
		params           map[string]json.RawMessage
		target           string
		setup            func(s *Scanner, bin string)
		out              []byte
		want, refuse     []string
		check            func(t *testing.T, raw []byte)
	}{
		{"subfinder", "discover.subdomains@1", params("sources", `["crtsh"]`, "recursive", `true`, "max_results", `1`), "example.com",
			func(s *Scanner, bin string) { s.Recon().(*subfinder.Scanner).Binary = bin }, subOut,
			[]string{"-sources crtsh", "-recursive"}, []string{"-all"},
			func(t *testing.T, raw []byte) {
				if n := strings.Count(string(raw), `"type":"subdomain"`); n != 1 {
					t.Fatalf("max_results 1 kept %d names", n)
				}
			}},
		{"dnsx", "resolve.dns@1", params("record_types", `["mx","txt"]`, "wildcard_filter", `true`), "example.com",
			func(s *Scanner, bin string) { s.Recon().(*dnsx.Scanner).Binary = bin }, dnsxOut,
			[]string{"-mx", "-txt", "-auto-wildcard"}, []string{"-cname"}, nil},
		{"httpx", "probe.http@1", params("ports", `"8080,8443"`, "tech_detect", `false`, "tls_grab", `false`), "example.com",
			func(s *Scanner, bin string) { s.Recon().(*httpx.Scanner).Binary = bin }, httpxOut,
			[]string{"-ports 8080,8443"}, []string{"-tech-detect", "-tls-grab"}, nil},
		{"katana", "crawl.web@1", params("depth", `2`, "js_parse", `false`, "max_urls", `1`), "https://example.com",
			func(s *Scanner, bin string) { s.Recon().(*katana.Scanner).Binary = bin }, katanaOut,
			[]string{"-d 2"}, []string{"-js-crawl"},
			func(t *testing.T, raw []byte) {
				if n := strings.Count(string(raw), `"type":"discovered_url"`); n > 1 {
					t.Fatalf("max_urls 1 kept %d URLs", n)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, "")
			s, err := New(tc.tool)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(s, checkingTool(t, tc.tool, tc.out, tc.want, tc.refuse))
			res, err := s.ScanTargets(context.Background(), []string{tc.target}, &core.ScanOptions{Capability: tc.capability, Params: tc.params})
			if err != nil {
				t.Fatalf("the params did not reach the engine: %v", err)
			}
			prov := provenanceOf(t, res.RawOutput)
			if !strings.Contains(prov, `"capability":"`+tc.capability+`"`) || strings.Contains(prov, "contract_violations") {
				t.Fatalf("provenance %s", prov)
			}
			if tc.check != nil {
				tc.check(t, res.RawOutput)
			}
		})
	}
}

// SECURITY: a param outside the descriptor's schema fails the job before
// any engine runs.
func TestCapabilityParamsRefused(t *testing.T) {
	withSensorResolver(t)
	cases := map[string]struct {
		tool, capability string
		params           map[string]json.RawMessage
		want             string
	}{
		"subfinder flag as source": {"subfinder", "discover.subdomains@1", params("sources", `["-o"]`), "sources"},
		"dnsx unknown type":        {"dnsx", "resolve.dns@1", params("record_types", `["axfr"]`), "not one of"},
		"httpx scheme ports":       {"httpx", "probe.http@1", params("ports", `"http:80"`), "ports"},
		"katana depth":             {"katana", "crawl.web@1", params("depth", `50`), "maximum"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, "")
			s, err := New(tc.tool)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ScanTargets(context.Background(), []string{"example.com"}, &core.ScanOptions{Capability: tc.capability, Params: tc.params})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
