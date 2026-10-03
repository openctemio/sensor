package subfinder

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

const helpFile = "subfinder-2.16.0.help"

func TestBuildArgs_Default(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	if got[0] != "-d" || got[1] != "example.com" || !slices.Contains(got, "-duc") || !slices.Contains(got, "-oJ") {
		t.Fatalf("args = %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}

func TestBuildArgs_EveryOptionIsDefined(t *testing.T) {
	s := NewScanner()
	s.RateLimit = 10
	s.Resolvers = []string{"1.1.1.1"}
	s.Sources = []string{"crtsh"}
	s.ExcludeSources = []string{"github"}
	s.All = true
	s.Recursive = true
	s.OutputFile = "/tmp/out.json"
	s.Proxy = "http://127.0.0.1:8080"
	flagcheck.Check(t, helpFile, s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/in.txt"}))
}

// Hosts below the root are subdomains, as ctis.ConvertReconToCTIS types
// them; the root itself is a domain.
func TestParse_SubdomainType(t *testing.T) {
	out := []byte(`{"host":"api.example.com","input":"example.com","source":"crtsh"}
{"host":"example.com","input":"example.com","source":"crtsh"}
`)
	r, err := (&Parser{}).Parse(context.Background(), out, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ctis.AssetType{}
	for _, a := range r.Assets {
		got[a.Value] = a.Type
	}
	if got["api.example.com"] != ctis.AssetTypeSubdomain || got["example.com"] != ctis.AssetTypeDomain {
		t.Fatalf("types = %v", got)
	}
}
