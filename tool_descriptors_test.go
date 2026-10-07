package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/sensor/internal/toolrun"
)

// Every built-in tool is described by its embedded tool.yaml and names the
// capabilities it implements from the OpenCTEM taxonomy. The descriptor the
// sensor reports hashes to its digest.
func TestBuiltinDescriptors(t *testing.T) {
	want := map[string][]string{
		"subfinder":   {"discover.subdomains@1"},
		"dnsx":        {"resolve.dns@1"},
		"naabu":       {"scan.ports@1"},
		"httpx":       {"probe.http@1"},
		"katana":      {"crawl.web@1"},
		"nuclei":      {"vuln.templates@1"},
		"semgrep":     {"sast.code@1"},
		"codeql":      {"sast.code@1"},
		"trivy":       {"sca.deps@1", "container.image@1", "iac.misconfig@1", "sbom.generate@1"},
		"betterleaks": {"secrets.code@1"},
		// The finding check (retest mode); it folds into nuclei once the
		// platform routes verify.finding.
		"nuclei-validate": {"verify.finding@1"},
	}
	seen := map[string]bool{}
	for _, tl := range toolrun.Registered() {
		m := tl.Manifest()
		seen[m.Name] = true
		exp, ok := want[m.Name]
		if !ok {
			t.Errorf("%s: a built-in tool without an expectation here", m.Name)
			continue
		}
		var got []string
		for _, im := range m.Implements {
			got = append(got, im.Capability)
		}
		if !slices.Equal(got, exp) {
			t.Errorf("%s implements %v, want %v", m.Name, got, exp)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("%s: %v", m.Name, err)
		}
		if len(m.Implements) > 0 && len(m.Capabilities) > 0 {
			t.Errorf("%s: the old capability words are reported by the scanner, not the descriptor", m.Name)
		}
		c := m.Contract()
		sum := sha256.Sum256(c.Descriptor)
		if len(c.Descriptor) == 0 || c.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Errorf("%s: the reported descriptor does not hash to its digest", m.Name)
		}
		if toolrun.Contract(m).Origin != "builtin" {
			t.Errorf("%s: a compiled-in tool reports origin builtin", m.Name)
		}
		if m.Presentation == nil || m.Engine == nil {
			t.Errorf("%s: presentation and engine are part of every built-in descriptor", m.Name)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s is not registered", name)
		}
	}
}

// `tools manifests --json` lists every descriptor with its digest.
func TestToolsCommandListsDescriptors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runToolsCommand([]string{"manifests", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var entries []toolManifestEntry
	if err := json.Unmarshal(out.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Digest == "" || e.Digest != e.Manifest.Digest() {
			t.Fatalf("%s: digest %q", e.Manifest.Name, e.Digest)
		}
	}
	n := len(entries)
	if n != len(builtinTools()) {
		t.Fatalf("listed %d of %d", n, len(builtinTools()))
	}
}
