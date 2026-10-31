package httpx

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func webScanner(t *testing.T) *Scanner {
	t.Helper()
	rs, err := NewScanner().WithCapability(WebContentCapability)
	if err != nil {
		t.Fatal(err)
	}
	return rs.(*Scanner)
}

func TestBuildArgs_WebContentOnlyForTheCapability(t *testing.T) {
	plain := NewScanner().buildArgs("example.com", nil)
	if slices.Contains(plain, "-irr") || slices.Contains(plain, "-response-size-to-read") {
		t.Fatalf("body flags without the capability: %q", plain)
	}
	other, _ := NewScanner().WithCapability("probe.http@1")
	if got := other.(*Scanner).buildArgs("example.com", nil); !slices.Equal(got, plain) {
		t.Fatalf("probe.http args changed: %q vs %q", got, plain)
	}
	args := webScanner(t).buildArgs("example.com", nil)
	i := slices.Index(args, "-response-size-to-read")
	if !slices.Contains(args, "-irr") || i < 0 || args[i+1] != strconv.Itoa(5<<20) {
		t.Fatalf("args = %q", args)
	}
	if slices.Contains(args, "-favicon") || slices.Contains(args, "-jarm") {
		t.Errorf("extra probes in a fetch: %q", args)
	}
	flagcheck.Check(t, helpFile, args, strconv.Itoa(5<<20))
}

func webOutput(contentType, body string) *HTTPXOutput {
	return &HTTPXOutput{URL: "https://example.com/p", Input: "https://example.com/p?x=1", StatusCode: 200, ContentType: contentType, Body: body}
}

func TestWebCapture_HashSizeAndInputURL(t *testing.T) {
	body := "console.log(1)"
	c := webCapture(webOutput("application/javascript", body), time.Unix(1790000000, 0))
	sum := sha256.Sum256([]byte(body))
	if c.SHA256 != hex.EncodeToString(sum[:]) || c.Size != int64(len(body)) || c.Body != body {
		t.Fatalf("capture = %+v", c)
	}
	if c.URL != "https://example.com/p?x=1" {
		t.Errorf("url = %q, want the input URL", c.URL)
	}
	if webCapture(&HTTPXOutput{URL: "https://example.com/", Input: "example.com"}, time.Unix(1790000000, 0)) != nil {
		t.Error("a line without a response gave a capture")
	}
	if got := webCapture(&HTTPXOutput{URL: "https://example.com/", Input: "example.com", StatusCode: 200}, time.Unix(1790000000, 0)); got.URL != "https://example.com/" {
		t.Errorf("a bare input must fall back to httpx's url: %q", got.URL)
	}
}

func TestWebCapture_BodyCapOnRuneBoundary(t *testing.T) {
	body := strings.Repeat("€", webBodyLimit/3+100) // 3-byte runes, the cap splits one
	c := webCapture(webOutput("text/html", body), time.Unix(1790000000, 0))
	if len(c.Body) > webBodyLimit || !utf8.ValidString(c.Body) || !c.BodyTruncated || len(c.Body) < webBodyLimit-3 {
		t.Fatalf("body %d bytes, valid=%v truncated=%v", len(c.Body), utf8.ValidString(c.Body), c.BodyTruncated)
	}
	sum := sha256.Sum256([]byte(body))
	if c.SHA256 != hex.EncodeToString(sum[:]) || c.Size != int64(len(body)) {
		t.Error("hash and size must describe all the bytes read, not the kept body")
	}
	if c.Truncated {
		t.Error("truncated set below the read limit")
	}
	if !webCapture(webOutput("text/plain", strings.Repeat("a", webReadLimit)), time.Unix(1790000000, 0)).Truncated {
		t.Error("truncated not set at the read limit")
	}
}

func TestWebCapture_ContentTypes(t *testing.T) {
	for ct, keep := range map[string]bool{
		"text/html; charset=utf-8": true, "text/plain": true, "text/css": true, "TEXT/HTML": true,
		"application/javascript": true, "text/javascript": true, "application/x-javascript": true,
		"application/json": true, "application/ld+json; charset=utf-8": true, "application/xhtml+xml": true,
		"image/png": false, "application/octet-stream": false, "application/zip": false, "application/pdf": false,
		"font/woff2": false, "": false, "not a type": false, "application/x-www-form;;": false,
	} {
		c := webCapture(webOutput(ct, "payload"), time.Unix(1790000000, 0))
		if got := c.Body != ""; got != keep {
			t.Errorf("%q: body kept = %v, want %v", ct, got, keep)
		}
		if c.SHA256 == "" {
			t.Errorf("%q: no hash", ct)
		}
	}
}

// The raw output the sensor keeps never holds the request, the raw headers or
// the body, whatever case httpx used.
func TestStripHeaders_DropsBodyRequestAndRawHeader(t *testing.T) {
	in := `{"url":"https://a/","Body":"SECRET-body","request":"GET /","raw_header":"Set-Cookie: SECRET","header":{"x":"SECRET"},"title":"t"}` + "\n"
	out := string(stripHeaders([]byte(in)))
	if strings.Contains(out, "SECRET") || strings.Contains(out, "GET /") || !strings.Contains(out, `"title":"t"`) {
		t.Fatalf("out = %s", out)
	}
	line := `{"url":"https://a/","title":"t"}` + "\n"
	if string(stripHeaders([]byte(line))) != line {
		t.Error("a line without those members changed")
	}
}

func TestParseOutput_WebContentOffByDefault(t *testing.T) {
	line := `{"url":"https://a.example/","input":"https://a.example/","status_code":200,"content_type":"text/html","body":"<html>"}` + "\n"
	hosts, _, err := NewScanner().parseOutput([]byte(line))
	if err != nil || len(hosts) != 1 || hosts[0].WebContent != nil {
		t.Fatalf("%v %v", hosts, err)
	}
	hosts, _, err = webScanner(t).parseOutput([]byte(line))
	if err != nil || len(hosts) != 1 || len(hosts[0].WebContent) != 1 || hosts[0].WebContent[0].Body != "<html>" {
		t.Fatalf("%v %v", hosts, err)
	}
}

// A 5 MiB body that JSON escapes to several times its size still parses in a
// web content job.
func TestParseOutput_LargeBodyLine(t *testing.T) {
	body := strings.Repeat("\x01", webReadLimit)
	line := `{"url":"https://a.example/","input":"https://a.example/","status_code":200,"content_type":"text/plain","body":"` +
		strings.Repeat(`\u0001`, webReadLimit) + `"}` + "\n"
	hosts, _, err := webScanner(t).parseOutput([]byte(line))
	if err != nil || len(hosts) != 1 {
		t.Fatalf("%v %d", err, len(hosts))
	}
	c := hosts[0].WebContent[0]
	if c.Size != int64(len(body)) || len(c.Body) != webBodyLimit || !c.Truncated {
		t.Fatalf("size %d body %d truncated %v", c.Size, len(c.Body), c.Truncated)
	}
}
