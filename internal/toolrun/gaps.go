package toolrun

import (
	"encoding/json"
	"slices"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/webdiff"
)

// Coverage gaps a tool child found itself (a tool with its own host
// breaker) travel to the sensor in its report's properties, under the
// result metadata's key names (core.MetaCoverageGaps,
// core.MetaCoverageGapsTotal): a hand-over between the sensor's own
// processes, never sent. The sensor takes them off the report
// (TakeReportGaps) and states every gap of the run, the child's and the
// task forwarder's, as the host's CTIS metadata.targets entry
// (ApplyGapTargets). The child reads target-controlled data, so what comes
// back is checked: a known reason, a bounded host, at most
// adapt.TargetRate.MaxGaps entries.

const maxGapField = 256

// discoveryGaps are the origin gap reasons of path discovery (webguess,
// pkg/webdiff); "blocked" is adapt.GapBlocked. Such a gap names the origin
// ("https://app.example.com:8443") as its host, its reason the main one, and
// its detail every reason met with the number of candidates it concerned
// ("catch_all=12 scope_filtered=3").
//
// GapNoCandidates is the reason of an origin on which no request was sent
// (an empty list, or nothing the scope leaves to request): the platform gives
// the origin's dispatch claim back.
const GapNoCandidates = "no_candidates"

var discoveryGaps = []string{GapNoCandidates, webdiff.GapCatchAll, webdiff.GapAuthWall, webdiff.GapEdgeProtected, webdiff.GapThrottled,
	webdiff.GapUnstableBaseline, webdiff.GapBudget, webdiff.GapHostileResponse, webdiff.GapProtocol, webdiff.GapScopeFiltered}

// SetReportGaps puts gaps (total counting also those not listed) in r's
// properties.
func SetReportGaps(r *ctis.Report, gaps []adapt.Gap, total int) {
	if r.Properties == nil {
		r.Properties = ctis.Properties{}
	}
	r.Properties[core.MetaCoverageGaps] = gaps
	r.Properties[core.MetaCoverageGapsTotal] = max(total, len(gaps))
}

// TakeReportGaps reads the gaps a child put in its report's properties
// (ReportGaps) and removes them from the report.
func TakeReportGaps(r *ctis.Report) ([]adapt.Gap, int) {
	gaps, total := ReportGaps(r)
	if r != nil && r.Properties != nil {
		delete(r.Properties, core.MetaCoverageGaps)
		delete(r.Properties, core.MetaCoverageGapsTotal)
		if len(r.Properties) == 0 {
			r.Properties = nil
		}
	}
	return gaps, total
}

// ReportGaps reads the gaps a child put in its report's properties.
func ReportGaps(r *ctis.Report) ([]adapt.Gap, int) {
	if r == nil || r.Properties == nil {
		return nil, 0
	}
	raw, err := json.Marshal(r.Properties[core.MetaCoverageGaps])
	if err != nil {
		return nil, 0
	}
	var in []adapt.Gap
	if json.Unmarshal(raw, &in) != nil {
		return nil, 0
	}
	var out []adapt.Gap
	for _, g := range in {
		switch g.Reason {
		case adapt.GapBreakerOpen, adapt.GapRateFloor, adapt.GapBlocked, adapt.GapThrottled:
		default:
			if !slices.Contains(discoveryGaps, g.Reason) {
				continue
			}
		}
		if g.Host == "" || len(g.Host) > maxGapField {
			continue
		}
		if len(g.Detail) > maxGapField {
			g.Detail = g.Detail[:maxGapField]
		}
		if len(out) < adapt.TargetRate.MaxGaps {
			out = append(out, g)
		}
	}
	total := 0
	if f, ok := r.Properties[core.MetaCoverageGapsTotal].(float64); ok && f > 0 && f < 1e6 {
		total = int(f)
	} else if n, ok := r.Properties[core.MetaCoverageGapsTotal].(int); ok && n > 0 && n < 1e6 {
		total = n
	}
	if len(out) == 0 {
		return nil, 0
	}
	return out, max(total, len(out))
}

// ApplyGapTargets states each coverage gap in r's metadata.targets: the
// entry of every target on the gap's host that the run marked done becomes
// failed with the gap's class (an edge block or challenge, a rate limit, a
// host that stopped answering), and a gap host no entry names gets an entry
// of its own. A gap of the sensor's own path (the job's proxy pool did not
// carry the connections) says nothing about the target: its target is
// unfinished, never failed on the target's side. Targets that were skipped
// or already failed keep their outcome.
func ApplyGapTargets(r *ctis.Report, gaps []adapt.Gap) {
	if r == nil || len(gaps) == 0 {
		return
	}
	for _, g := range gaps {
		o, ok := gapOutcome(g)
		if !ok {
			continue
		}
		host := reach.HostOf(g.Host)
		matched := false
		for i := range r.Metadata.Targets {
			t := &r.Metadata.Targets[i]
			if reach.HostOf(t.Target) != host {
				continue
			}
			matched = true
			if t.State == ctis.TargetDone {
				t.State, t.Class, t.Cause = o.State, o.Class, o.Cause
			}
		}
		if !matched && len(r.Metadata.Targets) < ctis.MaxTargets {
			o.Target = g.Host
			r.Metadata.Targets = append(r.Metadata.Targets, o)
		}
	}
	if r.Metadata.CoverageType == ctis.CoverageFull || r.Metadata.CoverageType == "" {
		r.Metadata.CoverageType = ctis.CoveragePartial
	}
}

// gapOutcome is the outcome of a target whose host is a coverage gap.
func gapOutcome(g adapt.Gap) (ctis.TargetOutcome, bool) {
	o := ctis.TargetOutcome{State: ctis.TargetFailed, Cause: ctis.TargetCauseTarget}
	switch g.Reason {
	case adapt.GapBlocked:
		o.Class = ctis.TargetClassEdgeBlocked
		if g.Edge == "challenged" {
			o.Class = ctis.TargetClassEdgeChallenged
		}
	case adapt.GapRateFloor:
		o.Class = ctis.TargetClassRateLimited
	case adapt.GapBreakerOpen:
		o.Class = ctis.TargetClassUnreachable
	case adapt.GapProxyUnavailable:
		return ctis.TargetOutcome{State: ctis.TargetUnfinished}, true
	// Path discovery's origin gaps (webguess, pkg/webdiff): an edge or a
	// rate limit that stopped the origin is the host's outcome; the other
	// reasons (catch_all, auth_wall, budget, ...) leave the target done and
	// only make the run partial.
	case webdiff.GapEdgeProtected:
		o.Class = ctis.TargetClassEdgeBlocked
		if g.Edge == "challenged" {
			o.Class = ctis.TargetClassEdgeChallenged
		}
	case webdiff.GapThrottled:
		o.Class = ctis.TargetClassRateLimited
	default:
		return ctis.TargetOutcome{}, false
	}
	return o, true
}
