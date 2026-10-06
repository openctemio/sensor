package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// A scanner without its own parser that writes SARIF (CodeQL) goes through
// the SDK's SARIF parser, which runs on the ctis importer: the findings are
// filed on the scanned repository, the branch the sensor detected is the
// report's branch (it gates auto-resolve on the platform), and a secret
// scanner's raw match never reaches the report.
func TestScannerSARIF_ThroughImporter(t *testing.T) {
	const raw = "AKIAZXCVBNMQWERTYUIO"
	out := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":[{"id":"js/sql-injection","properties":{"tags":["security","external/cwe/cwe-089"]}}]}},
	  "results":[{"ruleId":"js/sql-injection","level":"error","message":{"text":"SQL injection"},
	    "partialFingerprints":{"primaryLocationLineHash":"39fa2ee980eb94b0:1"},
	    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.js"},"region":{"startLine":12}}}]}]},
	  {"tool":{"driver":{"name":"gitleaks","rules":[{"id":"aws-access-token"}]}},
	  "results":[{"ruleId":"aws-access-token","message":{"text":"AWS access key"},
	    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"cfg.env"},"region":{"startLine":3,"snippet":{"text":"KEY=` + raw + `"}}}}]}]}]}`)
	parser, err := newParserRegistryWith(nil).ForScanner("codeql", out)
	if err != nil {
		t.Fatal(err)
	}
	branch := &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}
	report, err := parser.Parse(context.Background(), out, &core.ParseOptions{
		ToolName:   "codeql",
		AssetType:  ctis.AssetTypeRepository,
		AssetValue: "github.com/example/shop",
		Branch:     "main",
		BranchInfo: branch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctis.CheckFindingAssets(report); err != nil {
		t.Fatal(err)
	}
	if len(report.Assets) != 1 || report.Assets[0].Value != "github.com/example/shop" {
		t.Fatalf("assets = %+v", report.Assets)
	}
	if b := report.Metadata.Branch; b == nil || b.Name != "main" || !b.IsDefaultBranch {
		t.Errorf("branch = %+v, want main (default)", b)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}
	f := report.Findings[0]
	if f.RuleID != "js/sql-injection" || f.Severity != ctis.SeverityHigh || f.Location == nil || f.Location.Path != "src/db.js" ||
		f.PartialFingerprints["primaryLocationLineHash"] != "39fa2ee980eb94b0:1" {
		t.Errorf("codeql finding = %+v", f)
	}
	if b, _ := json.Marshal(report); strings.Contains(string(b), raw) {
		t.Errorf("raw secret in the report: %s", b)
	}
}
