package dnsx

import (
	"os"
	"slices"
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// Real dnsx 1.3.1 output (example.com, -a).
func TestParseOutput_Real(t *testing.T) {
	data, err := os.ReadFile(flagcheck.Testdata("dnsx-1.3.1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	recs, err := NewScanner().parseOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Host != "example.com" || recs[0].RecordType != "A" ||
		!slices.Equal(recs[0].Values, []string{"104.20.23.154", "172.66.147.243"}) {
		t.Fatalf("records = %+v", recs)
	}
}
