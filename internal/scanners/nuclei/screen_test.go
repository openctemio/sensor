package nuclei

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

func httpFinding(status int, headers map[string]string, body string, tags ...string) ctis.Finding {
	resp := &ctis.EvidenceResponse{Status: status, Body: body}
	for k, v := range headers {
		resp.Headers = append(resp.Headers, ctis.EvidenceHeader{Name: k, Value: v})
	}
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityHigh, AssetRef: "a", Tags: tags,
		EvidenceItems: []ctis.EvidenceItem{{Kind: "http_exchange", HTTP: &ctis.EvidenceHTTP{
			Request:  &ctis.EvidenceRequest{Method: "GET", URL: "https://app.example.com/x"},
			Response: resp,
		}}}}
}

var tokenRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

func TestScreenFinding(t *testing.T) {
	challenge := map[string]string{"X-Amzn-Waf-Action": "challenge"}
	for _, tc := range []struct {
		name    string
		f       ctis.Finding
		reasons []string
		status  int
		edge    string
	}{
		{"clean 200", httpFinding(200, nil, "<html>admin</html>"), nil, 0, ""},
		{"a 403 alone is not a block", httpFinding(403, nil, "Forbidden"), nil, 0, ""},
		{"429", httpFinding(429, nil, "slow down"), []string{ctis.HoldThrottledResponse}, 429, ""},
		{"503", httpFinding(503, nil, "Service Unavailable"), []string{ctis.HoldThrottledResponse}, 503, ""},
		{"Retry-After on a 200", httpFinding(200, map[string]string{"Retry-After": "30"}, "ok"), []string{ctis.HoldThrottledResponse}, 200, ""},
		{"edge challenge", httpFinding(202, challenge, ""), []string{ctis.HoldEdgeBlockPage}, 202, "challenged"},
		{"edge challenge on a WAF detection template is its finding", httpFinding(202, challenge, "", "tech", "waf"), nil, 0, ""},
		{"time-based template", httpFinding(200, nil, "ok", "sqli", "Time-Based"), []string{ctis.HoldTimingBased}, 0, ""},
		{"several reasons in order", httpFinding(429, nil, "x", "time-based"), []string{ctis.HoldThrottledResponse, ctis.HoldTimingBased}, 429, ""},
		{"no HTTP evidence", ctis.Finding{Title: "t", Tags: []string{"cve"}}, nil, 0, ""},
	} {
		h, ok := screenFinding(&tc.f)
		if ok != (tc.reasons != nil) || !slices.Equal(h.Reasons, tc.reasons) || h.Status != tc.status || h.Edge != tc.edge {
			t.Errorf("%s: %v %+v, want reasons %v status %d edge %q", tc.name, ok, h, tc.reasons, tc.status, tc.edge)
			continue
		}
		if ok {
			if err := h.Validate(); err != nil {
				t.Errorf("%s: invalid hold %+v: %v", tc.name, h, err)
			}
			if h.EdgeVendor != "" && !tokenRE.MatchString(h.EdgeVendor) {
				t.Errorf("%s: vendor %q is not a token", tc.name, h.EdgeVendor)
			}
		}
	}
}

// A report keeps every finding; the screened ones carry the hold, the
// others are untouched.
func TestScreenReportKeepsEveryFinding(t *testing.T) {
	r := ctis.NewReport()
	r.Findings = []ctis.Finding{httpFinding(200, nil, "ok"), httpFinding(429, nil, "x"), httpFinding(503, nil, "y")}
	if n := screenReport(r); n != 2 {
		t.Fatalf("held %d, want 2", n)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("findings %d: a finding was dropped", len(r.Findings))
	}
	if _, ok, _ := r.Findings[0].VerificationHold(); ok {
		t.Error("the clean finding is held")
	}
	for _, i := range []int{1, 2} {
		h, ok, err := r.Findings[i].VerificationHold()
		if !ok || err != nil || h.Reasons[0] != ctis.HoldThrottledResponse {
			t.Errorf("finding %d: %+v %v %v", i, h, ok, err)
		}
	}
	if screenReport(nil) != 0 {
		t.Error("nil report")
	}
}

func TestVendorToken(t *testing.T) {
	for in, want := range map[string]string{
		"":               "",
		"Example Edge":   "example-edge",
		" <b>Bad</b> ":   "bbadb",
		"edge.example_1": "edge.example_1",
		"---":            "",
	} {
		if got := vendorToken(in); got != want {
			t.Errorf("vendorToken(%q) = %q, want %q", in, got, want)
		}
	}
	long := vendorToken("a" + strings.Repeat("b", 100))
	if len(long) > 64 {
		t.Errorf("token of %d", len(long))
	}
}
