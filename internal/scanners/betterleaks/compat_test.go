package betterleaks

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/importparse"
	"github.com/openctemio/sensor/internal/scanners/internal/reporttest"
)

// The same finding as gitleaks 8.30.0 and betterleaks 1.9.0 write it for one
// secret (`dir` scan of /scan): identical fields and fingerprint, plus the
// Attributes object betterleaks adds. The secret is a placeholder.
const (
	gitleaksReport = `[{"RuleID":"github-pat","Description":"Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.","StartLine":3,"EndLine":3,"StartColumn":17,"EndColumn":56,"Match":"GITHUB_TOKEN = \"placeholder-secret-value-0001\"","Secret":"placeholder-secret-value-0001","File":"/scan/src/config.py","SymlinkFile":"","Commit":"","Entropy":4.821928,"Author":"","Email":"","Date":"","Message":"","Tags":[],"Fingerprint":"/scan/src/config.py:github-pat:3"}]`

	betterleaksReport = `[{"RuleID":"github-pat","Description":"Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.","StartLine":3,"EndLine":3,"StartColumn":17,"EndColumn":56,"Match":"GITHUB_TOKEN = \"placeholder-secret-value-0001\"","Secret":"placeholder-secret-value-0001","File":"/scan/src/config.py","SymlinkFile":"","Commit":"","Entropy":4.821928,"Author":"","Email":"","Date":"","Message":"","Tags":[],"Fingerprint":"/scan/src/config.py:github-pat:3","Attributes":{"confidence":"high","path":"/scan/src/config.py","resource":"fs.content"}}]`
)

// A secret both tools report must keep its identity across the switch: same
// fingerprint, same masked value, same rule (the platform's finding
// fingerprint is built from path, rule, line and masked value).
func TestGitleaksAndBetterleaksReportsGiveTheSameFinding(t *testing.T) {
	// A repository to file the finding on (WP-S2: no asset-less findings).
	opts := &core.ParseOptions{BasePath: "/scan", AssetValue: "github.com/org/repo"}
	gl, err := importparse.Betterleaks().Parse(context.Background(), []byte(gitleaksReport), opts)
	if err != nil {
		t.Fatalf("gitleaks report: %v", err)
	}
	bl, err := importparse.Betterleaks().Parse(context.Background(), []byte(betterleaksReport), opts)
	if err != nil {
		t.Fatalf("betterleaks report: %v", err)
	}
	if len(gl.Findings) != 1 || len(bl.Findings) != 1 {
		t.Fatalf("want 1 finding each, got %d and %d", len(gl.Findings), len(bl.Findings))
	}
	g, b := gl.Findings[0], bl.Findings[0]
	if g.Fingerprint != b.Fingerprint || b.Fingerprint != "src/config.py:github-pat:3" {
		t.Errorf("fingerprints differ: gitleaks %q, betterleaks %q", g.Fingerprint, b.Fingerprint)
	}
	if g.Secret.MaskedValue != b.Secret.MaskedValue || g.RuleID != b.RuleID || g.Location.Path != b.Location.Path {
		t.Errorf("identity differs: gitleaks %+v / %+v, betterleaks %+v / %+v", g.Secret, g.Location, b.Secret, b.Location)
	}
	// Both are reported as betterleaks: one secret-scanner identity.
	if gl.Tool.Name != core.ScannerBetterleaks || bl.Tool.Name != core.ScannerBetterleaks {
		t.Errorf("tool names = %q, %q; want %q", gl.Tool.Name, bl.Tool.Name, core.ScannerBetterleaks)
	}
	// ctis/importer gives every secret-scanner finding one confidence;
	// betterleaks Attributes.confidence is not read.
	if b.Confidence != 85 || g.Confidence != b.Confidence {
		t.Errorf("confidence = %d / %d, want 85", g.Confidence, b.Confidence)
	}
}

func TestParseRefusesV2Envelope(t *testing.T) {
	_, err := ParseJSONBytes([]byte(`{"schema_version":"1","findings":[],"scan":{}}`))
	if !errors.Is(err, ErrV2Report) {
		t.Fatalf("v2 envelope: err = %v, want ErrV2Report", err)
	}
	if f, err := ParseJSONBytes([]byte(`[]`)); err != nil || len(f) != 0 {
		t.Fatalf("empty v1 report: %v, %v", f, err)
	}
}

// Neither betterleaks nor gitleaks `dir` accepts --exclude-path or --no-git;
// passing them made every scan with exclusions fail.
func TestBuildArgsOnlyPassesSupportedFlags(t *testing.T) {
	s := NewScanner()
	args := s.buildArgs("/scan", "/tmp/r.json", &core.SecretScanOptions{Exclude: []string{"vendor"}, NoGit: true, ConfigFile: "/cfg.toml"})
	for _, bad := range []string{"--exclude-path", "--no-git"} {
		if slices.Contains(args, bad) {
			t.Errorf("args contain unsupported flag %s: %v", bad, args)
		}
	}
	want := []string{"dir", "/scan", "--report-format", "json", "--report-path", "/tmp/r.json", "--exit-code", "0", "--no-banner", "--config", "/cfg.toml", "--ignore-gitleaks-allow"}
	if !slices.Equal(args, want) {
		t.Errorf("args = %v\nwant   %v", args, want)
	}
}

// A verbose scanner must not make the tool print raw secrets into the log.
func TestBuildArgsNeverPassesVerbose(t *testing.T) {
	s := NewScanner()
	s.Verbose = true
	if args := s.buildArgs("/scan", "/tmp/r.json", nil); slices.Contains(args, "--verbose") || slices.Contains(args, "-v") {
		t.Fatalf("args = %v: --verbose prints raw secrets", args)
	}
}

func TestFilterExcluded(t *testing.T) {
	findings := []Finding{
		{File: "/scan/src/a.py"},
		{File: "/scan/vendor/lib/b.go"},
		{File: "/scan/testdata/fixture.env"},
		{File: "/scan/pkg/bundle.zip!inner/c.env"},
		{File: "/scan/docs/key.pem"},
	}
	got := filterExcluded(findings, "/scan", []string{"vendor/", "./testdata", "pkg/*.zip", "*.pem"})
	if len(got) != 1 || got[0].File != "/scan/src/a.py" {
		t.Fatalf("kept %+v, want only src/a.py", got)
	}
	if got := filterExcluded(findings, "/scan", nil); len(got) != len(findings) {
		t.Fatalf("no patterns kept %d of %d", len(got), len(findings))
	}
}

// Exclusions apply to the raw report GenericScan hands to the parser too.
func TestGenericScanAppliesExclusions(t *testing.T) {
	dir := t.TempDir()
	bin, _ := reporttest.FakeTool(t, `[{"RuleID":"r","File":"`+dir+`/vendor/x.go","Fingerprint":"f1"},{"RuleID":"r","File":"`+dir+`/main.go","Fingerprint":"f2"}]`)
	s := NewScanner()
	s.Binary = bin
	res, err := s.GenericScan(context.Background(), dir, &core.ScanOptions{Exclude: []string{"vendor"}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f, err := ParseJSONBytes(res.RawOutput)
	if err != nil {
		t.Fatalf("parse filtered report: %v", err)
	}
	if len(f) != 1 || f[0].Fingerprint != "f2" {
		t.Fatalf("filtered report = %+v, want only main.go", f)
	}
	if res.ScannerName != core.ScannerBetterleaks {
		t.Errorf("scanner name = %q", res.ScannerName)
	}
}
