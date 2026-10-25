package nuclei

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func msLine(path string, status string, matched bool, extraHeaders string) string {
	extraHeaders = strings.ReplaceAll(strings.ReplaceAll(extraHeaders, "\r", `\r`), "\n", `\n`)
	m := "false"
	if matched {
		m = "true"
	}
	return `{"template-id":"swagger-api","info":{"name":"s","severity":"info","tags":["exposure"]},"type":"http","host":"127.0.0.1:57931",` +
		`"matched-at":"http://127.0.0.1:57931` + path + `?token=abc123","request":"GET ` + path + ` HTTP/1.1\r\nHost: 127.0.0.1:57931\r\n\r\n",` +
		`"response":"HTTP/1.1 ` + status + `\r\n` + extraHeaders + `Content-Type: text/plain\r\n\r\nbody","timestamp":"2026-10-07T12:30:00Z","matcher-status":` + m + `}`
}

// A template that probes several paths reports each request, not only the
// exchange kept as evidence: the platform judges the finding's own endpoint
// from them.
func TestValidateResult_ReportsEveryRequest(t *testing.T) {
	out := strings.Join([]string{
		msLine("/v2/api-docs", "404 Not Found", false, ""),
		msLine("/swagger-ui/index.html", "403 Forbidden", false, "Server: cloudflare\r\nCF-RAY: 1\r\n"),
		msLine("/developers/documentation", "200 OK", true, ""),
		`{"template-id":"swagger-api","info":{"name":"s","severity":"info"},"type":"http","host":"127.0.0.1:57931","matcher-status":false,"error":"i/o timeout while GET http://127.0.0.1:57931/x?t=secret"}`,
	}, "\n") + "\n"
	res, err := ValidateSingleTemplateResult(&core.ExecResult{Stdout: []byte(out)}, nil, ValidateOptions{Target: "http://127.0.0.1:57931", TemplateID: "swagger-api"})
	if err != nil || res.Outcome != OutcomeDetected {
		t.Fatalf("%+v %v", res, err)
	}
	if len(res.Requests) != 4 {
		t.Fatalf("want 4 requests, got %+v", res.Requests)
	}
	if r := res.Requests[0]; !r.Matched || !strings.HasSuffix(r.URL, "/developers/documentation") || r.Status != 200 {
		t.Errorf("a match comes first: %+v", r)
	}
	var edge, timeout bool
	for _, r := range res.Requests {
		if strings.Contains(r.URL, "abc123") || strings.Contains(r.URL, "secret") {
			t.Errorf("a query value left the sensor: %+v", r)
		}
		if strings.HasSuffix(r.URL, "/swagger-ui/index.html") && r.Status == 403 && r.EdgeVendor == "cloudflare" && !r.Matched {
			edge = true
		}
		if r.Error == "timeout" && r.Status == 0 {
			timeout = true
		}
	}
	if !edge || !timeout {
		t.Errorf("edge=%v timeout=%v in %+v", edge, timeout, res.Requests)
	}
}

func TestValidateResult_NoMatchKeepsRequests(t *testing.T) {
	out := msLine("/a", "404 Not Found", false, "") + "\n" + msLine("/b", "404 Not Found", false, "") + "\n"
	res, _ := ValidateSingleTemplateResult(&core.ExecResult{Stdout: []byte(out)}, nil, ValidateOptions{Target: "http://127.0.0.1:57931", TemplateID: "swagger-api"})
	if res.Outcome != OutcomeNotDetected || len(res.Requests) != 2 || res.Requests[1].Status != 404 {
		t.Fatalf("%+v", res)
	}
}
