package nuclei

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// Hosts nuclei skipped as unresponsive were not reached: a timeout (the
// ambiguous class) unless nuclei named a permanent error; gaps from
// anything else and hosts outside the job are not recorded.
func TestRecordUnresponsive(t *testing.T) {
	stderr := "[INF] Skipped a.example.test:443 from target list as found unresponsive 30 times\n" +
		"[INF] Skipped b.example.test:80 from target list as found unresponsive permanently: no address found for host\n" +
		"[INF] Skipped other.example.test:443 from target list as found unresponsive 30 times\n"
	gaps, _ := coverageGaps(stderr)
	gaps = append(gaps, adapt.Gap{Host: "c.example.test", Reason: adapt.GapBreakerOpen, Detail: "the forwarder's breaker opened"})
	res := &core.ScanResult{}
	res.AddCoverageGaps(gaps, len(gaps))

	rec := reach.NewRecorder()
	recordUnresponsive(reach.WithRecorder(context.Background(), rec),
		[]string{"https://a.example.test", "http://b.example.test", "c.example.test"}, res)
	rep := rec.Report()
	if rep.Targets != 2 || rep.Classes[reach.Timeout] != 1 || rep.Classes[reach.DNSFailure] != 1 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	for _, u := range rep.UnreachedList {
		if u.Target != "https://a.example.test" && u.Target != "http://b.example.test" {
			t.Errorf("recorded %q", u.Target)
		}
	}
	recordUnresponsive(context.Background(), nil, nil) // no result, no recorder: no panic
}
