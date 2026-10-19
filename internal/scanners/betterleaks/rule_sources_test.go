package betterleaks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/openctemio/sdk-go/pkg/core"
)

const orgRules = `
title = "org"

[[rules]]
id = "aws-access-token"
description = "same id as a default rule"
regex = '''ORG[0-9]{8}'''

[[rules]]
id = "internal-token"
regex = '''itk_[a-z0-9]{20}'''
`

type mergedConfig struct {
	Extend struct {
		UseDefault bool   `toml:"useDefault"`
		Path       string `toml:"path"`
	} `toml:"extend"`
	Rules []struct {
		ID    string `toml:"id"`
		Regex string `toml:"regex"`
	} `toml:"rules"`
	Allowlist map[string]any `toml:"allowlist"`
}

func decodeMerged(t *testing.T, raw []byte) mergedConfig {
	t.Helper()
	var c mergedConfig
	if _, err := toml.Decode(string(raw), &c); err != nil {
		t.Fatalf("merged config is not TOML: %v\n%s", err, raw)
	}
	return c
}

// "both": the organization's rules extend the defaults (or the platform's
// config), every organization rule id is prefixed, so a rule with a
// default rule's id adds a rule instead of replacing the default one.
func TestBothExtendsThePlatformRules(t *testing.T) {
	raw, err := buildConfig([][]byte{[]byte(orgRules)}, core.RuleSourcesBoth, "")
	if err != nil {
		t.Fatal(err)
	}
	c := decodeMerged(t, raw)
	if !c.Extend.UseDefault || c.Extend.Path != "" {
		t.Fatalf("extend = %+v, want useDefault", c.Extend)
	}
	if len(c.Rules) != 2 || c.Rules[0].ID != "tenant:aws-access-token" || c.Rules[1].ID != "tenant:internal-token" || c.Rules[0].Regex != "ORG[0-9]{8}" {
		t.Fatalf("rules = %+v", c.Rules)
	}
	raw, err = buildConfig([][]byte{[]byte(orgRules)}, core.RuleSourcesBoth, "/content/betterleaks/rules.toml")
	if err != nil {
		t.Fatal(err)
	}
	if c := decodeMerged(t, raw); c.Extend.Path != "/content/betterleaks/rules.toml" || c.Extend.UseDefault {
		t.Fatalf("extend = %+v, want the platform config", c.Extend)
	}
}

// The organization cannot narrow or replace the platform's rules in a
// "both" scan, and can never make the scanner read or fetch other files.
func TestBothRefusesWhatWouldDisablePlatformRules(t *testing.T) {
	base := "[[rules]]\nid = \"x\"\nregex = '''x'''\n"
	for name, extra := range map[string]string{
		"global allowlist":  "[allowlist]\npaths = ['''.*''']\n",
		"global allowlists": "[[allowlists]]\nregexes = ['''.*''']\n",
		"useDefault false":  "[extend]\nuseDefault = false\n",
		"disabled rules":    "[extend]\nuseDefault = true\ndisabledRules = [\"aws-access-token\"]\n",
		"extend path":       "[extend]\npath = \"/etc/openctem/sensor-policy.yaml\"\n",
		"extend url":        "[extend]\nurl = \"https://example.com/rules.toml\"\n",
	} {
		if _, err := buildConfig([][]byte{[]byte(base + extra)}, core.RuleSourcesBoth, ""); err == nil {
			t.Errorf("%s: accepted in a both scan", name)
		}
	}
	if _, err := buildConfig([][]byte{[]byte("[[rules]]\nid = \"x\"\nID = \"aws-access-token\"\nregex = \"x\"\n")}, core.RuleSourcesBoth, ""); err == nil {
		t.Error("a rule with two id keys was accepted")
	}
	if _, err := buildConfig([][]byte{[]byte("foo = 1\n" + base)}, core.RuleSourcesBoth, ""); err == nil {
		t.Error("an unknown top-level key was accepted")
	}
	if _, err := buildConfig([][]byte{[]byte(base + "[extend]\nuseDefault = true\n")}, core.RuleSourcesBoth, ""); err != nil {
		t.Errorf("useDefault = true refused: %v", err)
	}
	if _, err := buildConfig([][]byte{[]byte("title = 'x'\n")}, core.RuleSourcesBoth, ""); err == nil {
		t.Error("a config without rules was accepted")
	}
}

// "tenant": the organization's rules alone, with its own allowlist and
// extend choices, but still never a file path or url.
func TestTenantOnlyKeepsTheOrganizationsChoices(t *testing.T) {
	raw, err := buildConfig([][]byte{[]byte(orgRules + "[allowlist]\npaths = ['''vendor/''']\n")}, core.RuleSourcesTenant, "/content/rules.toml")
	if err != nil {
		t.Fatal(err)
	}
	c := decodeMerged(t, raw)
	if c.Extend.UseDefault || c.Extend.Path != "" || c.Allowlist == nil || c.Rules[0].ID != "tenant:aws-access-token" {
		t.Fatalf("tenant config = %+v", c)
	}
	if _, err := buildConfig([][]byte{[]byte(orgRules + "[extend]\npath = \"/etc/passwd\"\n")}, core.RuleSourcesTenant, ""); err == nil {
		t.Fatal("extend path accepted for a tenant-only scan")
	}
}

func TestCustomConfigMergesEveryRuleFile(t *testing.T) {
	dir := t.TempDir()
	for n, b := range map[string]string{"a.toml": orgRules, "b.toml": "[[rules]]\nid = \"third\"\nregex = '''z'''\n", "notes.txt": "x"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path, cleanup, err := customConfig(dir, core.RuleSourcesBoth, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	raw, _ := os.ReadFile(path)
	if c := decodeMerged(t, raw); len(c.Rules) != 3 {
		t.Fatalf("rules = %+v, want all three files' rules", c.Rules)
	}
	if !strings.HasPrefix(path, os.TempDir()) || strings.HasPrefix(path, dir) {
		t.Fatalf("config %q written next to the received rules", path)
	}
	if _, _, err := customConfig(dir, core.RuleSourcesPlatform, ""); err == nil {
		t.Fatal("platform-only with custom rules accepted")
	}
	if _, _, err := customConfig(t.TempDir(), core.RuleSourcesBoth, ""); err == nil {
		t.Fatal("custom rules without a .toml file accepted")
	}
}
