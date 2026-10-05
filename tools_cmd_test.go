package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// toolsManifestsJSON runs `tools manifests --json` and returns the entries
// by tool name.
func toolsManifestsJSON(t *testing.T) map[string]toolManifestEntry {
	t.Helper()
	var out, errb bytes.Buffer
	if rc := runToolsCommand([]string{"manifests", "--json"}, &out, &errb); rc != 0 {
		t.Fatalf("exit %d: %s", rc, errb.String())
	}
	var entries []toolManifestEntry
	if err := json.Unmarshal(out.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	byName := map[string]toolManifestEntry{}
	for _, e := range entries {
		if _, dup := byName[e.Manifest.Name]; dup {
			t.Fatalf("%s listed twice", e.Manifest.Name)
		}
		if e.Digest != e.Manifest.Digest() {
			t.Fatalf("%s: digest %s, manifest digest %s", e.Manifest.Name, e.Digest, e.Manifest.Digest())
		}
		byName[e.Manifest.Name] = e
	}
	return byName
}

// requireListed fails unless every named tool is a compiled-in tool with a
// valid manifest in `tools manifests --json`.
func requireListed(t *testing.T, names ...string) {
	t.Helper()
	got := toolsManifestsJSON(t)
	for _, n := range names {
		e, ok := got[n]
		if !ok {
			t.Fatalf("%s is not listed by tools manifests (got %d tools)", n, len(got))
		}
		if err := e.Manifest.Validate(); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
}

func TestToolsManifestsListsTheContractTools(t *testing.T) {
	requireListed(t, "httpx", "nuclei", "subfinder", "dnsx")
}
