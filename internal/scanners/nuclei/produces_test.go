package nuclei

import (
	"context"
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/core"

	"github.com/openctemio/sensor/internal/scanners/importparse"
)

// The descriptor must declare every asset type the nuclei importer emits: the
// platform holds a report's assets, and the findings on them, for review when
// their type is not declared (a web origin was once missing, so the matches of
// a whole scan sat in the quarantine instead of the findings list).
func TestDescriptorDeclaresEveryAssetTypeTheReportCarries(t *testing.T) {
	var d struct {
		Produces []string `yaml:"produces"`
	}
	if err := yaml.Unmarshal(ToolYAML, &d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../importparse/testdata/nuclei_info_matches.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	r, err := importparse.Nuclei().Parse(context.Background(), raw, &core.ParseOptions{ToolName: "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) == 0 {
		t.Fatal("the fixture reports no asset")
	}
	for _, a := range r.Assets {
		if want := "asset:" + string(a.Type); !slices.Contains(d.Produces, want) {
			t.Errorf("tool.yaml produces does not declare %q, which a nuclei report carries", want)
		}
	}
}
