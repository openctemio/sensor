package toolrun

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Gaps a child puts in its report come back through the JSON a child
// sends; what the child got wrong is dropped.
func TestReportGapsRoundTrip(t *testing.T) {
	r := ctis.NewReport()
	SetReportGaps(r, []adapt.Gap{
		{Host: "a.example.test:443", Reason: adapt.GapBreakerOpen},
		{Host: "b.example.test", Reason: "made-up"},
		{Host: strings.Repeat("x", 300), Reason: adapt.GapBlocked},
		{Host: "c.example.test", Reason: adapt.GapRateFloor, Detail: strings.Repeat("d", 400)},
	}, 9)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back ctis.Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	gaps, total := ReportGaps(&back)
	if len(gaps) != 2 || gaps[0].Host != "a.example.test:443" || gaps[1].Host != "c.example.test" || total != 9 {
		t.Fatalf("gaps %+v total %d", gaps, total)
	}
	if len(gaps[1].Detail) != maxGapField {
		t.Fatalf("detail not bounded: %d", len(gaps[1].Detail))
	}
	if g, n := ReportGaps(ctis.NewReport()); g != nil || n != 0 {
		t.Fatal("gaps from a report without any")
	}
	if g, _ := ReportGaps(nil); g != nil {
		t.Fatal("gaps from no report")
	}
}
