package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/toolrun"
)

const watchedURL = "https://app.example.com/login"

func webLine(t *testing.T, contentType, body string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"url": watchedURL, "input": watchedURL, "host": "app.example.com", "scheme": "https", "port": "443",
		"status_code": 200, "content_type": contentType, "final_url": watchedURL + "/",
		"header": map[string]any{"set_cookie": "sid=SECRET-cookie; Secure"},
		"body":   body, "request": "GET /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n", "raw_header": "HTTP/1.1 200 OK\r\nSet-Cookie: sid=SECRET-cookie\r\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func runWebJob(t *testing.T, capability string, out []byte, want, refuse []string) *core.ScanResult {
	t.Helper()
	withSensorResolver(t)
	t.Setenv(toolrun.EnvRuntime, "")
	s, err := New("httpx")
	if err != nil {
		t.Fatal(err)
	}
	s.Recon().(*httpx.Scanner).Binary = checkingTool(t, "httpx", out, want, refuse)
	res, err := s.ScanTargets(context.Background(), []string{watchedURL}, &core.ScanOptions{Capability: capability})
	if err != nil {
		t.Fatalf("%s: %v", capability, err)
	}
	return res
}

func webContentOf(t *testing.T, raw []byte) []any {
	t.Helper()
	var rep struct {
		Assets []struct {
			Type       string         `json:"type"`
			Properties map[string]any `json:"properties"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	for _, a := range rep.Assets {
		if a.Type == "http_service" {
			wc, _ := a.Properties["web_content"].([]any)
			return wc
		}
	}
	return nil
}

// The capability job asks httpx for the response (-irr, read at most 5 MiB),
// reports url, hash, size and the text body as the web_content property, and
// the report holds no header, request or raw body member.
func TestWebContentJobReportsCapture(t *testing.T) {
	body := "<html><script src=/a.js></script></html>"
	res := runWebJob(t, "monitor.web_content@1", webLine(t, "text/html; charset=utf-8", body),
		[]string{"-irr", "-response-size-to-read 5242880"}, []string{"-favicon", "-jarm"})
	wc := webContentOf(t, res.RawOutput)
	if len(wc) != 1 {
		t.Fatalf("web_content = %v", wc)
	}
	c := wc[0].(map[string]any)
	sum := sha256.Sum256([]byte(body))
	if c["url"] != watchedURL || c["final_url"] != watchedURL+"/" || c["sha256"] != hex.EncodeToString(sum[:]) ||
		c["body"] != body || c["size"] != float64(len(body)) || c["status_code"] != float64(200) {
		t.Fatalf("capture = %v", c)
	}
	raw := string(res.RawOutput)
	for _, secret := range []string{"SECRET-cookie", "GET /login", "raw_header"} {
		if strings.Contains(raw, secret) {
			t.Errorf("report holds %q", secret)
		}
	}
}

// Without the capability the command line has no -irr and the report no
// web_content property, even when the tool printed a body.
func TestOtherJobsSendNoBodyFlags(t *testing.T) {
	res := runWebJob(t, "probe.http@1", webLine(t, "text/html", "<html></html>"), nil, []string{"-irr", "-response-size-to-read"})
	if wc := webContentOf(t, res.RawOutput); wc != nil {
		t.Fatalf("web_content on a probe.http job: %v", wc)
	}
	if strings.Contains(string(res.RawOutput), "<html>") {
		t.Fatal("a body reached the report")
	}
}

func TestWebContentJobBinaryKeepsNoBody(t *testing.T) {
	res := runWebJob(t, "monitor.web_content@1", webLine(t, "image/png", "\x89PNG-bytes"), nil, nil)
	c := webContentOf(t, res.RawOutput)[0].(map[string]any)
	if b, _ := c["body"].(string); b != "" {
		t.Fatalf("binary body kept: %q", b)
	}
	if c["sha256"] == "" || c["size"] == float64(0) {
		t.Fatalf("capture = %v", c)
	}
}
