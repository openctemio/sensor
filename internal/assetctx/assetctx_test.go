package assetctx

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestHostAsset(t *testing.T) {
	cases := []struct {
		in    string
		typ   ctis.AssetType
		value string
	}{
		{"https://Example.com:8443/path?q=1", ctis.AssetTypeDomain, "example.com"},
		{"example.com", ctis.AssetTypeDomain, "example.com"},
		{"example.com/login", ctis.AssetTypeDomain, "example.com"},
		{"10.0.0.7:3000", ctis.AssetTypeIPAddress, "10.0.0.7"},
		{"http://[2001:db8::1]:80/", ctis.AssetTypeIPAddress, "2001:db8::1"},
		{"192.168.1.1", ctis.AssetTypeIPAddress, "192.168.1.1"},
		{"", "", ""},
		{"https://", "", ""},
	}
	for _, tc := range cases {
		typ, value := HostAsset(tc.in)
		if typ != tc.typ || value != tc.value {
			t.Errorf("HostAsset(%q) = %q, %q; want %q, %q", tc.in, typ, value, tc.typ, tc.value)
		}
	}
}

func TestHosts_DeduplicatesAndReferences(t *testing.T) {
	r := ctis.NewReport()
	h := NewHosts(r)
	a := h.Ref("https://example.com/a")
	b := h.Ref("example.com:443")
	c := h.Ref("10.0.0.1")
	if a != b || a == c || h.Ref("") != "" {
		t.Fatalf("refs = %q %q %q", a, b, c)
	}
	if len(r.Assets) != 2 {
		t.Fatalf("assets = %+v, want 2", r.Assets)
	}
}

func TestBindOrFail(t *testing.T) {
	r := ctis.NewReport()
	if err := BindOrFail(r, ctis.Asset{}, false, "x"); err != nil {
		t.Fatalf("no findings, no asset: %v", err)
	}
	r.Findings = append(r.Findings, ctis.Finding{}, ctis.Finding{AssetRef: "stale"})
	if err := BindOrFail(r, ctis.Asset{}, false, "x"); err == nil {
		t.Fatal("findings without an asset: want an error")
	}
	if err := BindOrFail(r, ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/o/r"}, true, "x"); err != nil {
		t.Fatal(err)
	}
	if err := ctis.CheckFindingAssets(r); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.AssetRef != DefaultID {
			t.Errorf("asset_ref = %q, want %q", f.AssetRef, DefaultID)
		}
	}
}

func TestRepository_FromCI(t *testing.T) {
	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	if _, ok := Repository(nil); ok {
		t.Fatal("outside CI with no options: want no repository")
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "org/app")
	t.Setenv("GITHUB_SERVER_URL", "https://github.example.com")
	t.Setenv("GITHUB_SHA", "abc")
	t.Setenv("GITHUB_EVENT_PATH", "")
	a, ok := Repository(&core.ParseOptions{})
	if !ok || a.Value != "github.example.com/org/app" || a.Properties["commit_sha"] != "abc" {
		t.Fatalf("asset = %+v, ok = %v", a, ok)
	}
}
