package httpx

import (
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Web content capture (capability monitor.web_content@1).
//
// The job lists URLs; httpx fetches each once and the sensor reports the
// response the platform needs to see whether a page or a script changed:
// status, content type, size, SHA-256 and a capped text body. Nothing is
// executed or rendered. The body is hostile input: it is read up to
// webReadLimit bytes, hashed as read, and kept only for text-like content
// types up to webBodyLimit bytes. It never reaches a log line, and the raw
// output the sensor keeps has the request, headers and body members removed
// (stripResponse).

// WebContentCapability is the capability that turns the capture on.
const WebContentCapability = "monitor.web_content@1"

const (
	// webReadLimit is httpx's response-size-to-read (-rstr): the most body
	// bytes it reads and decompresses.
	webReadLimit = 5 << 20
	// webBodyLimit is the most body bytes the sensor keeps.
	webBodyLimit = 512 << 10
)

// WithCapability returns the scanner configured for a capability job. For
// monitor.web_content it asks httpx for the response body and fetches each URL
// once, without the favicon and JARM probes (extra requests). Any other
// capability leaves the scanner as it is.
func (s *Scanner) WithCapability(ref string) (core.ReconScanner, error) {
	if ref != WebContentCapability {
		return s, nil
	}
	c := *s
	c.WebContent = true
	c.Favicon = false
	c.Jarm = false
	return &c, nil
}

// webCapture is the capture of one httpx line: url is the input URL (what the
// platform watches), not httpx's normalised one. It returns nil when the line
// carries no response (the URL did not answer).
func webCapture(o *HTTPXOutput, now time.Time) *core.WebCapture {
	if o.StatusCode == 0 {
		return nil
	}
	url := o.URL
	if in := strings.TrimSpace(o.Input); strings.HasPrefix(in, "http://") || strings.HasPrefix(in, "https://") {
		url = in
	}
	sum := sha256.Sum256([]byte(o.Body))
	c := &core.WebCapture{
		URL:         url,
		FinalURL:    o.FinalURL,
		StatusCode:  o.StatusCode,
		ContentType: o.ContentType,
		Size:        int64(len(o.Body)),
		SHA256:      hex.EncodeToString(sum[:]),
		Truncated:   len(o.Body) >= webReadLimit,
		FetchedAt:   now.UTC(),
	}
	if keepsBody(o.ContentType) {
		c.Body = o.Body
		if len(c.Body) > webBodyLimit {
			c.Body = cutUTF8(c.Body, webBodyLimit)
			c.BodyTruncated = true
		}
	}
	return c
}

// keepsBody reports whether a content type is text, HTML, JavaScript or JSON:
// the only bodies the platform can compare as text. No content type, an
// image, an archive or any binary type keeps no body (the hash still says
// whether it changed).
func keepsBody(contentType string) bool {
	mt, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
	if err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(mt, "text/"):
		return true
	case mt == "application/javascript", mt == "application/x-javascript", mt == "application/ecmascript",
		mt == "application/json", mt == "application/xhtml+xml", strings.HasSuffix(mt, "+json"):
		return true
	}
	return false
}

// cutUTF8 cuts s to at most n bytes on a character boundary.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// webReadArgs are httpx's flags for the capture: the response (headers and
// body) in the JSON line, and the size it reads.
func webReadArgs() []string {
	return []string{"-irr", "-response-size-to-read", strconv.Itoa(webReadLimit)}
}
