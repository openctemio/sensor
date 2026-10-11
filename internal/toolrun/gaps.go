package toolrun

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Coverage gaps a tool child found itself (a tool with its own host
// breaker) travel in its report's properties, under the result metadata's
// key names (core.MetaCoverageGaps, core.MetaCoverageGapsTotal). The child
// reads target-controlled data, so what comes back is checked: a known
// reason, a bounded host, at most adapt.TargetRate.MaxGaps entries.

const maxGapField = 256

// SetReportGaps puts gaps (total counting also those not listed) in r's
// properties.
func SetReportGaps(r *ctis.Report, gaps []adapt.Gap, total int) {
	if r.Properties == nil {
		r.Properties = ctis.Properties{}
	}
	r.Properties[core.MetaCoverageGaps] = gaps
	r.Properties[core.MetaCoverageGapsTotal] = max(total, len(gaps))
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
		case adapt.GapBreakerOpen, adapt.GapRateFloor, adapt.GapBlocked:
		default:
			continue
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
