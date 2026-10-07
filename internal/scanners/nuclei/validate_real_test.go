package nuclei

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Lines nuclei v3 printed with -ms for a template that ran and did not
// match (a 404), and for a target whose port was closed (captured from the
// real binary).
const (
	realNoMatch = `{"template-id":"ms-probe","info":{"name":"ms probe","severity":"info","tags":["misc"]},"type":"http","host":"127.0.0.1:57931","request":"GET /vuln HTTP/1.1\r\nHost: 127.0.0.1:57931\r\nUser-Agent: Mozilla/5.0\r\nAuthorization: Bearer fakebearer9999\r\nAccept-Encoding: gzip\r\n\r\n","response":"HTTP/1.0 404 Not Found\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nnot found","timestamp":"2026-10-07T11:30:00Z","matcher-status":false}`
	realClosed = `{"template-id":"ms-probe","info":{"name":"ms probe","severity":"info","tags":["misc"]},"type":"http","host":"127.0.0.1:57939","timestamp":"2026-10-07T11:30:01Z","matcher-status":false,"error":"port closed or filtered"}`
)

func TestValidateResult_RealMatcherStatusLines(t *testing.T) {
	opts := ValidateOptions{Target: "http://127.0.0.1:57931", TemplateID: "ms-probe"}
	res, err := ValidateSingleTemplateResult(&core.ExecResult{Stdout: []byte(realNoMatch + "\n")}, nil, opts)
	if err != nil || res.Outcome != OutcomeNotDetected || len(res.EvidenceItems) != 1 {
		t.Fatalf("no match: %+v %v", res, err)
	}
	ex := res.EvidenceItems[0]
	if ex.HTTP.Response == nil || ex.HTTP.Response.Status != 404 || ex.HTTP.Request == nil || len(ex.Sensitive) == 0 {
		t.Fatalf("attempt %+v", ex)
	}
	res, _ = ValidateSingleTemplateResult(&core.ExecResult{Stdout: []byte(realClosed + "\n")}, nil, opts)
	if res.Outcome != OutcomeInconclusive || res.Evidence["error_class"] != "connection refused" {
		t.Fatalf("closed port: %+v", res)
	}
}

// nuclei masks Authorization and Cookie itself ("***", seen on the real
// 3.x binary even for a header the template sets): the evidence keeps the
// masked value as it came, and nothing raw is invented.
func TestValidateResult_NucleiMaskedHeadersKept(t *testing.T) {
	line := `{"template-id":"ms-probe","info":{"name":"p","severity":"info","tags":["misc"]},"type":"http","host":"127.0.0.1:57931","request":"GET /vuln HTTP/1.1\r\nHost: 127.0.0.1:57931\r\nAuthorization: ***\r\nCookie: ***\r\n\r\n","response":"HTTP/1.1 404 Not Found\r\n\r\nnot found","timestamp":"2026-10-07T12:30:00Z","matcher-status":false}`
	res, err := ValidateSingleTemplateResult(&core.ExecResult{Stdout: []byte(line + "\n")}, nil, ValidateOptions{Target: "http://127.0.0.1:57931", TemplateID: "ms-probe"})
	if err != nil || len(res.EvidenceItems) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, h := range res.EvidenceItems[0].HTTP.Request.Headers {
		if (h.Name == "Authorization" || h.Name == "Cookie") && h.Value != "***" {
			t.Fatalf("%s = %q, want nuclei's mask kept", h.Name, h.Value)
		}
	}
}
