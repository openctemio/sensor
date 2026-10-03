package nuclei

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Managed templates (api RFC-031): a scan that runs a managed template set
// must not let nuclei update or replace it, and skips templates whose
// signature does not match.
func TestBuildArgsManagedTemplates(t *testing.T) {
	s := NewScanner()
	s.TemplateDir = "/var/lib/openctem/content/nuclei-templates/v10.4.9"
	s.DisableUpdateCheck = true
	s.DisableUnsignedTemplates = true

	args := s.buildArgs("https://example.com", &core.ScanOptions{})
	for _, want := range []string{"-disable-update-check", "-disable-unsigned-templates"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
	if i := slices.Index(args, "-t"); i < 0 || args[i+1] != s.TemplateDir {
		t.Errorf("template dir not passed: %v", args)
	}

	// Platform-provided templates are not signed by the publisher: the
	// signature filter would drop them all, so it is not applied.
	args = s.buildArgs("https://example.com", &core.ScanOptions{CustomTemplateDir: "/tmp/tenant-templates"})
	if slices.Contains(args, "-disable-unsigned-templates") {
		t.Errorf("signature filter applied to custom templates: %v", args)
	}
	if !slices.Contains(args, "-disable-update-check") {
		t.Errorf("update check not disabled with custom templates: %v", args)
	}

	// Defaults are unchanged.
	args = NewScanner().buildArgs("https://example.com", nil)
	if slices.Contains(args, "-disable-update-check") || slices.Contains(args, "-disable-unsigned-templates") {
		t.Errorf("default scanner gained flags: %v", args)
	}
}

func TestBuildValidateArgsTemplatesDir(t *testing.T) {
	args, err := buildValidateArgs(ValidateOptions{
		Target: "https://example.com", TemplateID: "CVE-2021-44228",
		TemplatesDir: "/content/nuclei-templates/current",
	})
	if err != nil {
		t.Fatal(err)
	}
	ti, ii := slices.Index(args, "-t"), slices.Index(args, "-id")
	if ti < 0 || args[ti+1] != "/content/nuclei-templates/current" || ii < 0 || args[ii+1] != "CVE-2021-44228" {
		t.Fatalf("args %v", args)
	}

	// Without a directory the lookup is nuclei's own (unchanged).
	args, err = buildValidateArgs(ValidateOptions{Target: "https://example.com", TemplateID: "CVE-2021-44228"})
	if err != nil || slices.Contains(args, "-t") {
		t.Fatalf("args %v %v", args, err)
	}

	if _, err := buildValidateArgs(ValidateOptions{
		Target: "https://example.com", TemplateID: "x", TemplatesDir: "-u",
	}); err == nil {
		t.Fatal("flag-shaped templates dir accepted")
	}
}
