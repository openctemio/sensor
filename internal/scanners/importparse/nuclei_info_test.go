package importparse

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Real nuclei v3.11.1 output (templates v10.5.1, default sensor arguments
// with info included) against a local test origin serving /.env and
// /.git/config: 2 tech-detect and 10 http-missing-security-headers info
// matches next to the medium and high ones. Every severity reaches the
// report; the sensor never drops info matches (the platform decides where
// they go).
func TestNucleiInfoMatchesReachTheReport(t *testing.T) {
	data, err := os.ReadFile("testdata/nuclei_info_matches.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Nuclei().Parse(context.Background(), data, &core.ParseOptions{ToolName: "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	bySev := map[string]int{}
	for _, f := range r.Findings {
		bySev[string(f.Severity)]++
	}
	if bySev["info"] != 12 || bySev["medium"] != 1 || bySev["high"] != 1 {
		t.Fatalf("findings by severity = %v, want info 12, medium 1, high 1", bySev)
	}
}
