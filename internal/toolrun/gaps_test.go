package toolrun

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/webdiff"
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

// The hand-over leaves the report: TakeReportGaps returns the gaps and the
// report keeps no coverage_gaps property.
func TestTakeReportGapsRemovesTheHandOver(t *testing.T) {
	r := ctis.NewReport()
	SetReportGaps(r, []adapt.Gap{{Host: "a.example.test", Reason: adapt.GapBreakerOpen}}, 1)
	gaps, total := TakeReportGaps(r)
	if len(gaps) != 1 || total != 1 {
		t.Fatalf("gaps %+v total %d", gaps, total)
	}
	if r.Properties != nil {
		t.Fatalf("properties kept: %v", r.Properties)
	}
}

// Every coverage gap lands in metadata.targets with its class: a done
// target on the gap's host fails with the gap's class, a gap host the
// targets do not name gets its own entry, a skipped target keeps its
// outcome, and a proxy-pool gap leaves its target unfinished (the sensor's
// path, never the target's fault). The report stays valid CTIS.
func TestApplyGapTargets(t *testing.T) {
	r := ctis.NewReport()
	r.Metadata.ID = ctis.NewReportID()
	r.Metadata.CoverageType = ctis.CoverageFull
	r.Metadata.Targets = []ctis.TargetOutcome{
		{Target: "https://a.example.test/app", State: ctis.TargetDone},
		{Target: "b.example.test", State: ctis.TargetDone},
		{Target: "c.example.test", State: ctis.TargetSkipped, Class: ctis.TargetClassRefused},
		{Target: "d.example.test", State: ctis.TargetDone},
		{Target: "e.example.test", State: ctis.TargetDone},
		{Target: "ok.example.test", State: ctis.TargetDone},
	}
	ApplyGapTargets(r, []adapt.Gap{
		{Host: "a.example.test:443", Reason: adapt.GapBreakerOpen},
		{Host: "b.example.test", Reason: adapt.GapBlocked, Edge: "challenged"},
		{Host: "c.example.test", Reason: adapt.GapRateFloor},
		{Host: "d.example.test", Reason: adapt.GapProxyUnavailable},
		{Host: "e.example.test", Reason: adapt.GapRateFloor},
		{Host: "other.example.test", Reason: adapt.GapBlocked},
		{Host: "x.example.test", Reason: "made-up"},
	})
	want := []ctis.TargetOutcome{
		{Target: "https://a.example.test/app", State: ctis.TargetFailed, Class: ctis.TargetClassUnreachable, Cause: ctis.TargetCauseTarget},
		{Target: "b.example.test", State: ctis.TargetFailed, Class: ctis.TargetClassEdgeChallenged, Cause: ctis.TargetCauseTarget},
		{Target: "c.example.test", State: ctis.TargetSkipped, Class: ctis.TargetClassRefused},
		{Target: "d.example.test", State: ctis.TargetUnfinished},
		{Target: "e.example.test", State: ctis.TargetFailed, Class: ctis.TargetClassRateLimited, Cause: ctis.TargetCauseTarget},
		{Target: "ok.example.test", State: ctis.TargetDone},
		{Target: "other.example.test", State: ctis.TargetFailed, Class: ctis.TargetClassEdgeBlocked, Cause: ctis.TargetCauseTarget},
	}
	if len(r.Metadata.Targets) != len(want) {
		t.Fatalf("targets %+v", r.Metadata.Targets)
	}
	for i := range want {
		if r.Metadata.Targets[i] != want[i] {
			t.Fatalf("targets[%d] = %+v, want %+v", i, r.Metadata.Targets[i], want[i])
		}
	}
	if r.Metadata.CoverageType != ctis.CoveragePartial {
		t.Fatalf("coverage %q with gaps", r.Metadata.CoverageType)
	}
	if len(r.Properties) != 0 {
		t.Fatalf("properties %v", r.Properties)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("not valid CTIS: %v", err)
	}
}

// Path discovery's origin gaps come back from the child: its reasons are
// accepted (an unknown one is still dropped), an edge or a rate limit that
// stopped the origin becomes the host's outcome, and the other reasons leave
// the target done (the run is partial through its coverage gaps).
func TestDiscoveryGapsHandOver(t *testing.T) {
	var r ctis.Report
	SetReportGaps(&r, []adapt.Gap{
		{Host: "https://a.example.com", Reason: webdiff.GapEdgeProtected, Detail: "edge_protected=1", Edge: "challenged", Vendor: "cloudflare"},
		{Host: "https://b.example.com:8443", Reason: webdiff.GapCatchAll, Detail: "catch_all=12 scope_filtered=3"},
		{Host: "https://c.example.com", Reason: webdiff.GapThrottled, Detail: "throttled=1"},
		{Host: "https://d.example.com", Reason: "made_up"},
	}, 4)
	gaps, total := TakeReportGaps(&r)
	if len(gaps) != 3 || total != 4 {
		t.Fatalf("gaps %+v total %d", gaps, total)
	}
	r.Metadata.Targets = []ctis.TargetOutcome{
		{Target: "https://a.example.com", State: ctis.TargetDone},
		{Target: "https://b.example.com:8443", State: ctis.TargetDone},
		{Target: "https://c.example.com", State: ctis.TargetDone},
	}
	ApplyGapTargets(&r, gaps)
	want := map[string]string{"https://a.example.com": string(ctis.TargetClassEdgeChallenged), "https://c.example.com": string(ctis.TargetClassRateLimited)}
	for _, o := range r.Metadata.Targets {
		if c, ok := want[o.Target]; ok {
			if o.State != ctis.TargetFailed || string(o.Class) != c {
				t.Errorf("%s: %s/%s, want failed/%s", o.Target, o.State, o.Class, c)
			}
		} else if o.State != ctis.TargetDone {
			t.Errorf("%s: %s, want done", o.Target, o.State)
		}
	}
	if r.Metadata.CoverageType != ctis.CoveragePartial {
		t.Errorf("coverage %q", r.Metadata.CoverageType)
	}
}
