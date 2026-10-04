package semgrep

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// testdata/partial_parsing.json is real `semgrep 1.149.0 --json` output over a
// Go file and a JS file that each have one syntax error. Its errors[].type is
// an array, ["PartialParsing", [...]], and that used to make json.Unmarshal
// fail for the whole document: CanParse false, Parse error, every finding of
// the scan dropped.
func readPartialParsing(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "partial_parsing.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParser_PartialParsingKeepsFindings(t *testing.T) {
	data := readPartialParsing(t)
	p := &Parser{}
	if !p.CanParse(data) {
		t.Fatal("CanParse = false for real semgrep output with PartialParsing errors")
	}
	report, err := p.Parse(context.Background(), data, &core.ParseOptions{AssetValue: "github.com/example/app"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one per partially parsed file)", len(report.Findings))
	}
	rules := map[string]bool{}
	for _, f := range report.Findings {
		rules[f.RuleID] = true
	}
	if !rules["go-exec"] || !rules["js-exec"] {
		t.Errorf("rule ids = %v, want go-exec and js-exec", rules)
	}
}

func TestParseToSastResult_PartialParsingKeepsFindings(t *testing.T) {
	res, err := ParseToSastResult(readPartialParsing(t))
	if err != nil {
		t.Fatalf("ParseToSastResult: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
}

// semgrep emits a plain string for error kinds without a payload, and an
// array or object for others; every shape must parse.
func TestError_TypeShapes(t *testing.T) {
	for _, typ := range []string{`"Timeout"`, `["PartialParsing",[{"path":"a.go"}]]`, `{"kind":"x"}`} {
		in := []byte(`{"version":"1.149.0","errors":[{"code":3,"level":"warn","type":` + typ + `}],"results":[]}`)
		var out Report
		if err := json.Unmarshal(in, &out); err != nil {
			t.Errorf("type %s: %v", typ, err)
		}
	}
}
