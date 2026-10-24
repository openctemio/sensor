package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/edgeprotect"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// statusResult is a result line of a validation run with -ms, with whether
// nuclei wrote matcher-status at all (a line without it is a match, as
// nuclei prints it without -ms).
type statusResult struct {
	Result
	hasStatus bool
}

// splitResults sorts a validation run's lines: matches, attempts that ran
// and did not match, and requests that failed.
func splitResults(results []statusResult) (matches []Result, attempts, failures []statusResult) {
	for _, r := range results {
		switch {
		case !r.hasStatus || r.MatcherStatus:
			matches = append(matches, r.Result)
		case r.Error != "":
			failures = append(failures, r)
		default:
			attempts = append(attempts, r)
		}
	}
	return matches, attempts, failures
}

// statusLines decodes the JSON result lines of a validation run (one
// template, one target: a few lines), keeping whether each carried
// matcher-status. A line that is not a result is skipped.
func statusLines(data []byte) ([]statusResult, error) {
	var out []statusResult
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Result
		if json.Unmarshal(line, &r) != nil || r.TemplateID == "" {
			continue
		}
		var probe struct {
			Status *bool `json:"matcher-status"`
		}
		_ = json.Unmarshal(line, &probe)
		out = append(out, statusResult{Result: r, hasStatus: probe.Status != nil})
	}
	return out, sc.Err()
}

// exchangeEvidence is a run line's HTTP exchange and curl command as
// evidence items, raw with every sensitive value marked across both. A
// line without a request or response gives none.
//
// nuclei (3.x) masks Authorization and Cookie values itself ("***") in
// request and curl-command, whatever set them, and has no flag to turn that
// off (-rd only adds keys). Those values never reach the sensor, so they
// cannot be revealed on the platform; other credentials (Set-Cookie, query
// and body parameters, custom API-key headers) arrive raw and are marked.
func exchangeEvidence(r Result, matched bool) []ctis.EvidenceItem {
	base := firstNonEmptyString(r.Matched, r.URL, r.Host)
	ex, ok := ctis.HTTPExchangeFromRaw(r.Request, r.Response, base)
	if !ok {
		return nil
	}
	ex.Label = "attempt (no match)"
	if matched {
		ex.Label = "match"
		if r.MatcherName != "" {
			ex.Match = []ctis.EvidenceMatch{{Location: ctis.MatchLocationResponse, Part: ctis.MatchPartBody, Matcher: r.MatcherName}}
		}
		for _, e := range r.ExtractedResults {
			if len(ex.Extracted) == ctis.MaxEvidenceExtracted {
				break
			}
			ex.Extracted = append(ex.Extracted, capText(e, ctis.MaxEvidenceExtractLen))
		}
	}
	items := []ctis.EvidenceItem{ex}
	if c, ok := ctis.CurlEvidence(r.CurlCommand); ok {
		items = append(items, c)
	}
	ptrs := make([]*ctis.EvidenceItem, len(items))
	for i := range items {
		ptrs[i] = &items[i]
	}
	ctis.MarkSensitive(ptrs...)
	return items
}

// capVerdictEvidence keeps at most the evidence a verdict may carry.
func capVerdictEvidence(items []ctis.EvidenceItem) []ctis.EvidenceItem {
	if len(items) > tool.MaxVerdictEvidence {
		return items[:tool.MaxVerdictEvidence]
	}
	return items
}

// errorClass is a short class of a request error: the error text itself
// may carry the URL and its query, which never leaves the sensor.
func errorClass(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "timeout") || strings.Contains(m, "deadline"):
		return "timeout"
	case strings.Contains(m, "connection refused") || strings.Contains(m, "port closed"):
		return "connection refused"
	case strings.Contains(m, "no such host") || strings.Contains(m, "no address"):
		return "name not resolved"
	case strings.Contains(m, "tls") || strings.Contains(m, "certificate") || strings.Contains(m, "x509"):
		return "tls error"
	case strings.Contains(m, "reset") || strings.Contains(m, "eof"):
		return "connection reset"
	}
	return "request error"
}

// requestResults is one line per request of a validation run (with -ms
// nuclei writes one for every request: matches, attempts that did not
// match, requests that failed), so the platform can judge the finding's own
// endpoint when the template probes several paths. At most
// tool.MaxVerdictRequests lines; matches first, so a cap never hides one.
func requestResults(results []statusResult) []tool.RequestResult {
	var matched, rest []tool.RequestResult
	for _, r := range results {
		base := firstNonEmptyString(r.Matched, r.URL, r.Host)
		line := tool.RequestResult{Matched: !r.hasStatus || r.MatcherStatus}
		ex, ok := ctis.HTTPExchangeFromRaw(r.Request, r.Response, base)
		if ok && ex.HTTP != nil && ex.HTTP.Request != nil && ex.HTTP.Request.URL != "" {
			// The request actually made (its own path), not the host.
			line.URL = requestURL(ex.HTTP.Request.URL)
		}
		if line.URL == "" {
			line.URL = requestURL(base)
		}
		if line.URL == "" {
			// A failed request names only its host.
			line.URL = requestHost(r.Host)
		}
		if line.URL == "" {
			continue
		}
		if r.Error != "" && !line.Matched {
			line.Error = errorClass(r.Error)
		} else if ok && ex.HTTP != nil && ex.HTTP.Response != nil {
			resp := ex.HTTP.Response
			line.Status = resp.Status
			h := http.Header{}
			for _, kv := range resp.Headers {
				h.Add(kv.Name, kv.Value)
			}
			if v := edgeprotect.Classify(resp.Status, h, "", []byte(resp.Body)); v.State != edgeprotect.Direct {
				line.EdgeVendor, line.EdgeState = v.Vendor, string(v.State)
			}
		}
		if line.Matched {
			matched = append(matched, line)
		} else {
			rest = append(rest, line)
		}
	}
	out := append(matched, rest...)
	if len(out) > tool.MaxVerdictRequests {
		out = out[:tool.MaxVerdictRequests]
	}
	return out
}

// requestURL is a request URL as it may leave the sensor: no userinfo, no
// fragment, query names without their values (a token travels in a value).
func requestURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.User, u.Fragment = nil, ""
	if q := u.Query(); len(q) > 0 {
		for k := range q {
			q[k] = []string{""}
		}
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// requestHost is a host[:port] as a URL-less label ("" when it holds
// anything but host characters).
func requestHost(h string) string {
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '[' || c == ']') {
			return ""
		}
	}
	return h
}
