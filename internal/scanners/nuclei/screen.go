package nuclei

// Match screen (research 518, P0-2): a nuclei match on a response that is
// the target's rate limit, challenge or block page, or a check that decides
// on response time, may be the target's answer, not the application. Such a
// finding is kept and marked with a CTIS verification hold
// (extensions["io.openctem"].verification_hold) so the platform holds it
// until it is checked. Nothing is dropped; only reason codes and the screen's
// inputs (status, edge answer and vendor) are added, never response content.
//
// v0 reads the finding's own HTTP evidence: a 429 or 503 status or a
// Retry-After (throttled_response), an edge protection that challenged or
// blocked (edge_block_page; a template whose subject is the edge itself,
// such as waf-detect, is not screened for it), and time-based templates
// (timing_based). The origin baseline (soft_404) and out-of-band rules
// (oob_weak) come later.

import (
	"net/http"
	"slices"
	"strings"

	"github.com/openctemio/contract/edgeprotect"
	"github.com/openctemio/ctis/v2"
)

// edgeSubjectTags mark templates that detect the edge protection itself:
// matching one is their finding, not a block.
var edgeSubjectTags = []string{"waf", "cdn"}

// timingTags mark templates that decide on response time.
var timingTags = []string{"time-based", "timing", "time-delay"}

// screenReport marks the findings of a nuclei report whose matched response
// may be the target's throttling or block answer. It returns how many it
// marked.
func screenReport(r *ctis.Report) int {
	if r == nil {
		return 0
	}
	n := 0
	for i := range r.Findings {
		f := &r.Findings[i]
		h, ok := screenFinding(f)
		if !ok {
			continue
		}
		if err := f.SetVerificationHold(h); err == nil {
			n++
		}
	}
	return n
}

// screenFinding returns the hold of one finding, and false when nothing in
// its evidence suggests one.
func screenFinding(f *ctis.Finding) (ctis.VerificationHold, bool) {
	var h ctis.VerificationHold
	add := func(reason string) {
		if !slices.Contains(h.Reasons, reason) {
			h.Reasons = append(h.Reasons, reason)
		}
	}
	tags := lowerTags(f.Tags)
	edgeSubject := hasAny(tags, edgeSubjectTags)
	for _, e := range f.EvidenceItems {
		if e.HTTP == nil || e.HTTP.Response == nil {
			continue
		}
		resp := e.HTTP.Response
		hdr := http.Header{}
		for _, kv := range resp.Headers {
			hdr.Add(kv.Name, kv.Value)
		}
		if resp.Status == http.StatusTooManyRequests || resp.Status == http.StatusServiceUnavailable || hdr.Get("Retry-After") != "" {
			add(ctis.HoldThrottledResponse)
			if h.Status == 0 && resp.Status >= 100 && resp.Status <= 599 {
				h.Status = resp.Status
			}
		}
		if edgeSubject {
			continue
		}
		body := resp.Body
		if resp.BodyEncoding == ctis.BodyEncodingBase64 {
			// A binary body says nothing a block page would.
			body = ""
		}
		switch v := edgeprotect.Classify(resp.Status, hdr, "", []byte(body)); v.State {
		case edgeprotect.Challenged, edgeprotect.Blocked:
			add(ctis.HoldEdgeBlockPage)
			h.Edge = string(v.State)
			h.EdgeVendor = vendorToken(v.Vendor)
			if h.Status == 0 && resp.Status >= 100 && resp.Status <= 599 {
				h.Status = resp.Status
			}
		case edgeprotect.RateLimited:
			add(ctis.HoldThrottledResponse)
			h.EdgeVendor = vendorToken(v.Vendor)
			if h.Status == 0 && resp.Status >= 100 && resp.Status <= 599 {
				h.Status = resp.Status
			}
		}
	}
	if hasAny(tags, timingTags) {
		add(ctis.HoldTimingBased)
	}
	if len(h.Reasons) == 0 {
		return ctis.VerificationHold{}, false
	}
	// Reasons in the format's order, so the same screen reads the same.
	slices.SortFunc(h.Reasons, func(a, b string) int {
		return slices.Index(ctis.HoldReasons, a) - slices.Index(ctis.HoldReasons, b)
	})
	return h, true
}

func lowerTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, strings.ToLower(strings.TrimSpace(t)))
	}
	return out
}

func hasAny(tags, want []string) bool {
	for _, t := range tags {
		if slices.Contains(want, t) {
			return true
		}
	}
	return false
}

// vendorToken reduces an edge vendor name to an open token (lower case,
// letters, digits, '-', '_' and '.', at most 64), or "" when nothing is left.
func vendorToken(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(v)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	s := strings.Trim(b.String(), "-_.")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
