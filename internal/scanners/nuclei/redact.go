package nuclei

// Evidence redaction for nuclei results (CTIS spec 4.8: no member of a report
// may hold a usable secret). Exposure and token templates extract the very
// credentials they find, and request/response/curl texts carry the scan's own
// Authorization and Cookie headers, so none of them is sent verbatim.
//
// Threat model: a report crosses the network, is logged or quarantined on
// rejection, is stored and shown to every reader of the finding, and may go
// to a non-OpenCTEM receiver. Redaction happens on the sensor, before the
// report exists. It errs on the side of hiding too much: an over-redacted
// header costs a little triage context, a leaked token is an incident.

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Size caps for evidence kept in finding properties. Redaction runs before
// the cut, so a secret is never left half-visible at the boundary.
const (
	maxRequestEvidence  = 4 << 10
	maxResponseEvidence = 8 << 10
	maxCurlEvidence     = 2 << 10
	maxExtractedResults = 20
	// minExtractedMaskLen is the shortest extracted value that is masked
	// wherever it appears in the request/response texts. Shorter values
	// (a status code, "ok") would shred the text without hiding anything.
	minExtractedMaskLen = 4
)

// redactedMarker replaces a hidden value.
const redactedMarker = "[REDACTED]"

// sensitiveNameParts marks a header, parameter or JSON key whose value is a
// credential when its lower-cased name contains one of them.
var sensitiveNameParts = []string{
	"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key",
	"access_key", "accesskey", "access-key", "auth", "session", "cookie",
	"credential", "private_key", "private-key", "privatekey", "signature", "jwt",
	"bearer", "csrf", "xsrf",
}

// sensitiveExactNames are short names that are credentials only as a whole
// name (as a substring they match too much: "design", "inside").
var sensitiveExactNames = map[string]struct{}{
	"key": {}, "sig": {}, "sid": {}, "code": {}, "pass": {}, "pin": {}, "otp": {},
}

func isSensitiveName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if _, ok := sensitiveExactNames[n]; ok {
		return true
	}
	for _, p := range sensitiveNameParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

var (
	// scheme://user:pass@ — userinfo in any URL inside a text.
	reURLUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)[^\s/@'"<>]+@`)
	// Name: value — HTTP headers, curl -H arguments, YAML/.env-like lines.
	reHeaderPair = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_\-]*)([ \t]*:[ \t]*)([^\r\n'"]*)`)
	// name=value — query strings, form bodies, .env lines, cookies.
	reQueryPair = regexp.MustCompile(`([A-Za-z0-9_.\-\[\]]+)=([^&\s;'"#,]*)`)
	// "name": "value" — JSON bodies.
	reJSONPair = regexp.MustCompile(`"([^"\\]{1,128})"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
)

// redactText hides credentials in an HTTP request, response or curl command:
// URL userinfo, the values of sensitive headers, parameters and JSON keys,
// and every extracted value, wherever it appears.
func redactText(s string, extracted []string) string {
	if s == "" {
		return ""
	}
	// Extracted values first: they are the template's own verdict on what
	// is sensitive, and must not survive in any other form.
	for _, v := range extracted {
		if utf8.RuneCountInString(v) >= minExtractedMaskLen {
			s = strings.ReplaceAll(s, v, redactedMarker)
		}
	}
	s = reURLUserinfo.ReplaceAllString(s, "${1}"+redactedMarker+"@")
	s = reJSONPair.ReplaceAllStringFunc(s, func(m string) string {
		g := reJSONPair.FindStringSubmatch(m)
		if !isSensitiveName(g[1]) {
			return m
		}
		return `"` + g[1] + `"` + g[2] + `"` + redactedMarker + `"`
	})
	s = reHeaderPair.ReplaceAllStringFunc(s, func(m string) string {
		g := reHeaderPair.FindStringSubmatch(m)
		if !isSensitiveName(g[1]) || strings.TrimSpace(g[3]) == "" {
			return m
		}
		return g[1] + g[2] + redactHeaderValue(g[3])
	})
	s = reQueryPair.ReplaceAllStringFunc(s, func(m string) string {
		g := reQueryPair.FindStringSubmatch(m)
		if !isSensitiveName(g[1]) || g[2] == "" || g[2] == redactedMarker {
			return m
		}
		return g[1] + "=" + redactedMarker
	})
	return s
}

// redactHeaderValue hides a credential header value, keeping a leading
// authentication scheme ("Bearer", "Basic") so the evidence still says how
// the request authenticated.
func redactHeaderValue(v string) string {
	if v == redactedMarker {
		return v
	}
	if i := strings.IndexByte(v, ' '); i > 0 {
		switch strings.ToLower(v[:i]) {
		case "bearer", "basic", "digest", "token", "negotiate", "ntlm", "aws4-hmac-sha256":
			return v[:i] + " " + redactedMarker
		}
	}
	return redactedMarker
}

// redactURL hides the userinfo and the values of sensitive query parameters
// of a URL, keeping the rest so the location stays useful.
func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return redactText(raw, nil)
	}
	if u.User != nil {
		u.User = url.User(redactedMarker)
	}
	if u.RawQuery != "" {
		u.RawQuery = reQueryPair.ReplaceAllStringFunc(u.RawQuery, func(m string) string {
			g := reQueryPair.FindStringSubmatch(m)
			if !isSensitiveName(g[1]) || g[2] == "" {
				return m
			}
			return g[1] + "=" + url.QueryEscape(redactedMarker)
		})
	}
	return u.String()
}

// sensitiveBodyTags are template tags whose response body is itself the
// exposed secret (an .env file, a key, a config dump). Such a body is never
// kept, only its size.
var sensitiveBodyTags = []string{
	"exposure", "exposures", "token", "tokens", "secret", "secrets", "credential",
	"credentials", "creds", "keys", "api-key", "apikey", "leak", "disclosure",
	"backup", "config", "env", "git", "default-login",
}

// redactResponse redacts a raw HTTP response. For templates that expose
// secrets the body is dropped; otherwise headers and body are redacted.
func redactResponse(resp string, tags, extracted []string) string {
	if resp == "" {
		return ""
	}
	if containsAny(tags, sensitiveBodyTags...) {
		head, body, ok := splitHTTPMessage(resp)
		if ok {
			if body == "" {
				return redactText(head, extracted)
			}
			return redactText(head, extracted) + fmt.Sprintf("\r\n\r\n[body redacted: %d bytes]", len(body))
		}
		return fmt.Sprintf("[response redacted: %d bytes]", len(resp))
	}
	return redactText(resp, extracted)
}

// splitHTTPMessage splits a raw HTTP message into its start line and headers
// and its body. ok is false when it does not look like an HTTP message.
func splitHTTPMessage(m string) (head, body string, ok bool) {
	if !strings.HasPrefix(m, "HTTP/") && !strings.Contains(firstLine(m), " HTTP/") {
		return "", "", false
	}
	if i := strings.Index(m, "\r\n\r\n"); i >= 0 {
		return m[:i], m[i+4:], true
	}
	if i := strings.Index(m, "\n\n"); i >= 0 {
		return m[:i], m[i+2:], true
	}
	return m, "", true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// maskExtracted masks each extracted value (at most maxExtractedResults)
// with the SDK's secret masking: an extracted value is what the template
// was written to find, which for exposure templates is a credential.
func maskExtracted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	n := len(values)
	if n > maxExtractedResults {
		n = maxExtractedResults
	}
	out := make([]string, 0, n)
	for _, v := range values[:n] {
		out = append(out, core.MaskSecret(v))
	}
	return out
}

// capText cuts s to at most maxBytes bytes on a rune boundary and marks the
// cut. Callers redact first, so the cut never exposes part of a secret.
func capText(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...[truncated]"
}
