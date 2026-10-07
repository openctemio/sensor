package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
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
	case strings.Contains(m, "connection refused"):
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
