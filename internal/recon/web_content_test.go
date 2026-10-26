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
	var posture map[string]any
	for _, a := range r.Assets {
		if p, ok := a.Properties["http_posture"].(map[string]any); ok {
			posture = p
			if a.Properties["cnames"] == nil {
				t.Error("cnames missing")
			}
		}
	}
	if posture == nil || posture["strict_transport_security"] != "max-age=1" || len(posture) != 2 {
		t.Fatalf("posture: %v", posture)
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
		if e.Path == "/login" && (e.ContentType != "text/html" || e.Parent != "https://app.example.com/") {
			t.Errorf("page endpoint: %+v", e)
		}
	}
}
