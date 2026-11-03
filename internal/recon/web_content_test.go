package recon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// The web content a probe and a crawler report reaches the CTIS report as
// the posture attribute and the form endpoints, and nothing outside the
// allow-list does, even when a result carries it.
func TestAppendResult_WebContent(t *testing.T) {
	in := &ctis.ReconToCTISInput{ScannerName: "web", ReconType: "http_probe", Target: "https://app.example.com"}
	appendResult(in, &core.ReconResult{
		LiveHosts: []core.LiveHost{{
			URL: "https://app.example.com", Host: "app.example.com", Scheme: "https", StatusCode: 200,
			CNAMEs: []string{"edge.cdn.net", "bad host"},
			// A result decoded from elsewhere can carry what the allow-list
			// drops: it must not get past appendResult.
			ResponseHeaders: &core.ResponseHeaders{
				Values:  map[string]string{"Strict-Transport-Security": "max-age=1", "Server": "SECRET-server", "X-Frame-Options": "a\r\nb"},
				Cookies: []core.CookieFlags{{Name: "sid", Secure: true}, {Name: "bad name"}},
			},
		}},
		URLs: []core.DiscoveredURL{{
			URL: "https://app.example.com/login", Source: "a", ContentType: "text/html", Parent: "https://app.example.com/",
			Forms: []core.WebForm{core.NewWebForm("POST", "https://app.example.com/session", []string{"email", "password"})},
		}},
	})
	in.ReconType = "default"
	r, err := ctis.ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), `a\r\nb`) {
		t.Errorf("a dropped value reached the report: %s", b)
	}
	// The posture is technical.http.security_headers on the web origin;
	// the alias chain is the host's CNAME records.
	var posture *ctis.SecurityHeaders
	cname := false
	for _, a := range r.Assets {
		if a.Technical == nil {
			continue
		}
		if h := a.Technical.HTTP; h != nil && h.SecurityHeaders != nil {
			posture = h.SecurityHeaders
		}
		if d := a.Technical.Domain; d != nil {
			for _, rec := range d.DNSRecords {
				if rec.Type == "CNAME" && rec.Value == "edge.cdn.net" {
					cname = true
				}
			}
		}
		if len(a.Properties) != 0 {
			t.Errorf("asset %s carries properties %v", a.Value, a.Properties)
		}
	}
	if posture == nil || posture.StrictTransportSecurity != "max-age=1" || posture.XFrameOptions != "" ||
		len(posture.Cookies) != 1 || posture.Cookies[0].Name != "sid" || !posture.Cookies[0].IsSecure {
		t.Fatalf("posture: %+v", posture)
	}
	if !cname {
		t.Error("cnames missing")
	}
	var login *ctis.Endpoint
	for i, e := range r.Endpoints {
		if e.Method == "POST" && e.Path == "/session" {
			login = &r.Endpoints[i]
		}
	}
	if login == nil || login.Kind != ctis.EndpointKindForm || len(login.Params) != 2 {
		t.Fatalf("form endpoint: %+v", r.Endpoints)
	}
	for _, p := range login.Params {
		if (p.Name == "password") != (p.TypeHint == "password") {
			t.Errorf("hint: %+v", p)
		}
	}
	for _, e := range r.Endpoints {
		if e.Path == "/login" && (e.ContentType != "text/html" || e.ParentURL != "https://app.example.com/") {
			t.Errorf("page endpoint: %+v", e)
		}
	}
}
