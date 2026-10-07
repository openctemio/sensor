package trivy

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/importparse"
	"github.com/openctemio/sensor/internal/toolrun"
)

// An sbom.generate@1 job lists every package and matches nothing: no
// vulnerability, misconfiguration or secret scanner runs.
func TestSBOMJobListsPackagesOnly(t *testing.T) {
	opts := &core.ScanOptions{Capability: CapabilitySBOM, Params: map[string]json.RawMessage{"dev_deps": json.RawMessage(`true`)}}
	_, mapped, err := toolrun.ApplyJob(context.Background(), ToolManifest, settingsSchema, opts)
	if err != nil {
		t.Fatal(err)
	}
	base := NewScanner()
	base.Scanners = []string{"vuln", "secret"}
	base.MisconfigScanners = []string{"helm"}
	sc, err := base.forScan(mapped)
	if err != nil {
		t.Fatal(err)
	}
	sc = sc.forCapability(mapped)
	args := sc.buildArgs("/src", mapped)
	if !slices.Contains(args, "--list-all-pkgs") || !slices.Contains(args, "--include-dev-deps") {
		t.Fatalf("args %v", args)
	}
	i := slices.Index(args, "--scanners")
	if i < 0 || args[i+1] != "license" || slices.Contains(args, "--misconfig-scanners") {
		t.Fatalf("an SBOM job must run the license scanner only: %v", args)
	}
	// The scanner itself is untouched (concurrent scans share it).
	if !slices.Equal(base.Scanners, []string{"vuln", "secret"}) || base.ListAllPkgs {
		t.Fatalf("base scanner modified: %+v", base)
	}
	// Another capability runs as configured.
	other := base.forCapability(&core.ScanOptions{Capability: "sca.deps@1"})
	if other != base {
		t.Fatal("sca.deps@1 must not change the scanner")
	}
}

// Trivy's package listing becomes dependencies, which is what the
// capability requires (dependencies with name and version).
func TestSBOMOutputBecomesDependencies(t *testing.T) {
	out := []byte(`{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[{"Target":"requirements.txt","Class":"lang-pkgs","Type":"pip","Packages":[{"ID":"flask@0.12","Name":"flask","Version":"0.12"},{"ID":"requests@2.19.0","Name":"requests","Version":"2.19.0"}]}]}`)
	r, err := importparse.Trivy().Parse(context.Background(), out, &core.ParseOptions{AssetType: "repository", AssetValue: "github.com/acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Dependencies) != 2 {
		t.Fatalf("findings %d dependencies %d", len(r.Findings), len(r.Dependencies))
	}
	for _, d := range r.Dependencies {
		if d.Name == "" || d.Version == "" {
			t.Fatalf("dependency without name or version: %+v", d)
		}
	}
}

func TestDescriptorImplementsSBOM(t *testing.T) {
	found := false
	for _, im := range ToolManifest.Implements {
		found = found || im.Capability == CapabilitySBOM
	}
	if !found {
		t.Fatal("trivy must implement sbom.generate@1")
	}
}
