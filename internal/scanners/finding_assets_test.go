package scanners_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/scanners/betterleaks"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/scanners/semgrep"
	"github.com/openctemio/sensor/internal/scanners/trivy"
)

// The parser fixtures, copied from sdk-go's pkg/adapters/testdata when the
// tool wrappers moved into the sensor.
const fixtures = "testdata"

// TestMain clears the CI markers: code parsers fall back to the CI job's
// repository, which would hide a missing repository on a CI runner.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	os.Exit(m.Run())
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtures, name)) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// repoOpts is what the sensor passes for a code scan: the repository it
// scanned.
func repoOpts() *core.ParseOptions {
	return &core.ParseOptions{AssetType: ctis.AssetTypeRepository, AssetValue: "github.com/example/shop"}
}

type parseFunc func(data []byte, opts *core.ParseOptions) (*ctis.Report, error)

func viaParser(p core.Parser) parseFunc {
	return func(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
		return p.Parse(context.Background(), data, opts)
	}
}

// Every parser the sensor uses, over its fixtures: every finding must
// resolve to an asset of its own report (ctis.CheckFindingAssets), the rule
// protocol v2 ingest enforces with no fallback asset.
func TestParsers_EveryFindingHasAnAsset(t *testing.T) {
	cases := []struct {
		name  string
		parse parseFunc
		input string
		opts  *core.ParseOptions
	}{
		{"core-sarif", viaParser(&core.SARIFParser{}), "sarif.sarif.json", repoOpts()},
		{"core-sarif-provenance", viaParser(&core.SARIFParser{}), "codeql-provenance.sarif.json", nil},
		{"core-sarif-codeql", viaParser(&core.SARIFParser{}), "codeql-provenance.sarif.json", repoOpts()},
		{"semgrep", viaParser(&semgrep.Parser{}), "semgrep.json", repoOpts()},
		{"betterleaks", viaParser(&betterleaks.Parser{}), "betterleaks.json", repoOpts()},
		{"trivy-image", viaParser(trivy.NewParser()), "trivy.json", nil},
		{"trivy-fs", viaParser(trivy.NewParser()), "trivy-fs.json", repoOpts()},
		{"nuclei", viaParser(&nuclei.ReportParser{}), "nuclei.jsonl", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := tc.parse(fixture(t, tc.input), tc.opts)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(report.Findings) == 0 {
				t.Fatal("fixture produced no finding: the case proves nothing")
			}
			if err := ctis.CheckFindingAssets(report); err != nil {
				t.Fatal(err)
			}
			for i, f := range report.Findings {
				if f.AssetRef == "" {
					t.Errorf("finding %d has no explicit asset_ref", i)
				}
			}
		})
	}
}

// A code scan with findings and no repository (no options, nothing in the
// log, not in CI) is an error: there is no shared fake asset to fall back to.
func TestParsers_NoRepositoryIsAnError(t *testing.T) {
	cases := []struct {
		name  string
		parse parseFunc
		input string
	}{
		{"core-sarif", viaParser(&core.SARIFParser{}), "sarif.sarif.json"},
		{"semgrep", viaParser(&semgrep.Parser{}), "semgrep.json"},
		{"betterleaks", viaParser(&betterleaks.Parser{}), "betterleaks.json"},
		{"trivy-fs", viaParser(trivy.NewParser()), "trivy-fs.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, opts := range []*core.ParseOptions{nil, {ToolName: tc.name}} {
				report, err := tc.parse(fixture(t, tc.input), opts)
				if !errors.Is(err, ctis.ErrNoAssetForFindings) {
					t.Fatalf("opts %+v: err = %v, want ctis.ErrNoAssetForFindings", opts, err)
				}
				if report != nil {
					t.Errorf("report = %+v, want nil", report)
				}
			}
		})
	}
}

// A nuclei result naming no host falls back to the scan target the caller
// passed, and without one the report is rejected.
func TestNuclei_ResultWithoutHost(t *testing.T) {
	line := []byte(`{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"type":"http","matcher-status":true}` + "\n")

	if _, err := (&nuclei.ReportParser{}).Parse(context.Background(), line, nil); !errors.Is(err, ctis.ErrNoAssetForFindings) {
		t.Fatalf("err = %v, want ctis.ErrNoAssetForFindings", err)
	}

	report, err := (&nuclei.ReportParser{}).Parse(context.Background(), line,
		&core.ParseOptions{AssetType: ctis.AssetTypeDomain, AssetValue: "shop.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Assets) != 1 || report.Assets[0].Value != "shop.example.com" {
		t.Fatalf("assets = %+v, want the scan target", report.Assets)
	}
	if err := ctis.CheckFindingAssets(report); err != nil {
		t.Fatal(err)
	}
}
