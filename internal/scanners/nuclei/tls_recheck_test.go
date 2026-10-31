package nuclei

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sensor/internal/tlscheck"
	"github.com/openctemio/sensor/internal/tlscheck/tlstest"
)

// A host that completes the TLS handshake and resets every request trips
// nuclei's host breaker. The run rechecks it: the gap says the host resets
// HTTP requests and serves an expired certificate, and its reach outcome is
// reached (it answered), never "unreachable".
func TestSkippedHostThatResetsIsRecheckedNotUnreachable(t *testing.T) {
	now := time.Now()
	host := tlstest.Serve(t, tlstest.Reset, tlstest.Cert(t, "ssl.default.pagebuilder.test", now.Add(-800*24*time.Hour), now.Add(-400*24*time.Hour)))
	restore := tlscheck.SetDialerForTesting(tlstest.Direct)
	defer restore()

	s := NewScanner()
	s.Binary = stubNucleiRun(t, "", "[INF] Skipped "+host+" from target list as found unresponsive 30 times\n", 0)
	res, err := s.run(context.Background(), []string{"-u", "https://" + host}, nil, nil, host)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.HasCoverageGaps() {
		t.Fatal("the host is still a coverage gap: it was not scanned")
	}
	g := res.CoverageGaps[0]
	if g.Reason != adapt.GapBreakerOpen || g.Cause != adapt.GapCauseHTTPReset || g.Cert != adapt.GapCertExpired {
		t.Fatalf("gap %+v", g)
	}
	if !strings.Contains(g.Detail, "TLS handshake completed, the HTTP request was reset") {
		t.Fatalf("detail %q", g.Detail)
	}

	rec := reach.NewRecorder()
	recordUnresponsive(reach.WithRecorder(context.Background(), rec), []string{"https://" + host}, res)
	rep := rec.Report()
	if rep.Classes[reach.Reached] != 1 || len(rep.UnreachedList) != 0 {
		t.Fatalf("a host that answered TLS was recorded as %+v", rep.Summary)
	}
}

func TestCauseClass(t *testing.T) {
	for cause, want := range map[string]reach.Class{
		adapt.GapCauseHTTPReset: reach.Reached, adapt.GapCauseTLSFailed: reach.Reached, adapt.GapCauseReset: reach.Reached,
		adapt.GapCauseAnswered: reach.Reached, adapt.GapCauseRefused: reach.PortClosed, adapt.GapCauseNoAnswer: reach.Timeout,
	} {
		if got, ok := causeClass(cause); !ok || got != want {
			t.Errorf("%s: %q %v", cause, got, ok)
		}
	}
	if _, ok := causeClass(""); ok {
		t.Error("no cause has a class")
	}
}
