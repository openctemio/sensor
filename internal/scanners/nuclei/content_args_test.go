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

	args := s.buildArgs("https://example.com", &core.ScanOptions{})
	for _, want := range []string{"-disable-update-check", "-disable-unsigned-templates"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
	if i := slices.Index(args, "-t"); i < 0 || args[i+1] != s.TemplateDir {
		t.Errorf("template dir not passed: %v", args)
	}

	// With custom templates the managed set still runs signature-checked,
	// and never together with the custom templates.
	custom := &core.ScanOptions{CustomTemplateDir: "/tmp/tenant-templates"}
	own := s.buildArgsFor("https://example.com", "", custom, passOwn)
	if !slices.Contains(own, "-disable-unsigned-templates") || slices.Contains(own, custom.CustomTemplateDir) {
		t.Errorf("own run with custom templates: %v", own)
	}
	if !slices.Contains(own, "-disable-update-check") {
		t.Errorf("update check not disabled with custom templates: %v", own)
	}
}

// The official templates are signed; every scan of them runs with
// -disable-unsigned-templates unless the operator turns it off in code.
func TestDefaultScannerRequiresSignedTemplates(t *testing.T) {
	args := NewScanner().buildArgs("https://example.com", nil)
	if !slices.Contains(args, "-disable-unsigned-templates") {
		t.Errorf("default scanner runs unsigned templates: %v", args)
	}
	for _, never := range []string{"-code", "-file", "-headless", "-esc", "-enable-self-contained", "-dast"} {
		if slices.Contains(args, never) {
			t.Errorf("default scanner passes %s: %v", never, args)
		}
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

// Every scan runs with -disable-update-check: nuclei never checks for or
// downloads templates (or an engine) at scan time, managed set or not.
func TestDefaultScannerNeverUpdates(t *testing.T) {
	for name, s := range map[string]*Scanner{"default": NewScanner(), "dast": NewDAST(), "vuln": NewVulnScanner()} {
		args := s.buildArgs("https://example.com", nil)
		if !slices.Contains(args, "-disable-update-check") || slices.Contains(args, "-ut") {
			t.Errorf("%s scanner args %v", name, args)
		}
	}
}
