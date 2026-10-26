package httpx

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

const hostileLine = `{"url":"https://example.com","input":"example.com","host":"example.com","scheme":"https","status_code":200,` +
	`"tech":["Nginx:1.25.3","PHP:8.2","PHP:8.2","HTTP/3","Foo:bar"],"cname":["Edge.CDN.net.","bad host"],` +
	`"header":{"strict_transport_security":"max-age=63072000","content_security_policy":"default-src 'self'",` +
	`"x_frame_options":"DENY","x_content_type_options":"nosniff","referrer_policy":"no-referrer",` +
	`"permissions_policy":"camera=()","access_control_allow_origin":"*","access_control_allow_credentials":"true",` +
	`"server":"SECRET-server","x_api_key":"SECRET-key","authorization":"SECRET-auth","x_debug_token":"SECRET-token",` +
	`"set_cookie":"sid=SECRET-cookie; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax, pref=SECRET-pref"}}` + "\n"

func TestBuildArgs_ResponseHeaders(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	if !slices.Contains(got, "-irh") {
		t.Errorf("no -irh: %q", got)
	}
	flagcheck.Check(t, helpFile, got)
	s := NewScanner()
	s.ResponseHeaders = false
	if slices.Contains(s.buildArgs("example.com", nil), "-irh") {
		t.Error("-irh with ResponseHeaders off")
	}
}

func TestParseOutput_PostureAllowList(t *testing.T) {
	hosts, techs, err := NewScanner().parseOutput([]byte(hostileLine))
	if err != nil || len(hosts) != 1 {
		t.Fatalf("%v %v", hosts, err)
	}
	h := hosts[0]
	if h.ResponseHeaders == nil || len(h.ResponseHeaders.Values) != 8 {
		t.Fatalf("values: %+v", h.ResponseHeaders)
	}
	if h.ResponseHeaders.Values["Strict-Transport-Security"] != "max-age=63072000" {
		t.Errorf("hsts: %v", h.ResponseHeaders.Values)
	}
	c := h.ResponseHeaders.Cookies
	if len(c) != 2 || c[0].Name != "pref" || c[1].Name != "sid" || !c[1].Secure || !c[1].HTTPOnly || c[1].SameSite != "lax" || !c[1].Persistent {
		t.Errorf("cookies: %+v", c)
	}
	if strings.Join(h.CNAMEs, ",") != "edge.cdn.net" {
		t.Errorf("cnames: %v", h.CNAMEs)
	}
	b, _ := json.Marshal(hosts)
	if strings.Contains(string(b), "SECRET") {
		t.Errorf("a disallowed header or a cookie value reached the host: %s", b)
	}

	got := map[string]string{}
	for _, tc := range techs {
		got[tc.Name] = tc.Version
	}
	if len(techs) != 4 || got["Nginx"] != "1.25.3" || got["PHP"] != "8.2" || got["HTTP/3"] != "" || got["Foo:bar"] != "" {
		t.Errorf("techs: %+v", techs)
	}
}

func TestParseOutput_HostileHeaderValues(t *testing.T) {
	for name, v := range map[string]string{
		"crlf": `max-age=1\r\nSet-Cookie: x=y`, "nul": `a\u0000b`, "1MiB": strings.Repeat("a", 1<<20), "bidi": `a\u202eb`,
	} {
		line := `{"url":"https://e.com","input":"e.com","header":{"strict_transport_security":"` + v + `"}}` + "\n"
		hosts, _, err := NewScanner().parseOutput([]byte(line))
		if err != nil || len(hosts) != 1 {
			t.Fatalf("%s: %v %v", name, hosts, err)
		}
		if hosts[0].ResponseHeaders != nil {
			t.Errorf("%s: value passed: %+v", name, hosts[0].ResponseHeaders)
		}
	}
	// A non-string header value and a cookie with a hostile name are ignored.
	line := `{"url":"https://e.com","input":"e.com","header":{"referrer_policy":["x"],"set_cookie":"bad name=1, ok=2"}}` + "\n"
	hosts, _, _ := NewScanner().parseOutput([]byte(line))
	if rh := hosts[0].ResponseHeaders; rh == nil || len(rh.Values) != 0 || len(rh.Cookies) != 1 || rh.Cookies[0].Name != "ok" {
		t.Errorf("%+v", hosts[0].ResponseHeaders)
	}
}

func TestResultFor_RawOutputHoldsNoHeaders(t *testing.T) {
	in := []byte(hostileLine + `{"url":"https://b.com","input":"b.com","HEADER":{"server":"SECRET-upper"}}` + "\n" + `not json "header" SECRET-junk` + "\n" + `{"url":"https://c.com","input":"c.com"}` + "\n")
	res, err := NewScanner().ResultFor("example.com", in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.RawOutput), "SECRET") || strings.Contains(strings.ToLower(string(res.RawOutput)), `"header"`) {
		t.Errorf("raw output holds headers: %s", res.RawOutput)
	}
	if !strings.Contains(string(res.RawOutput), "https://c.com") || !strings.Contains(string(res.RawOutput), `"status_code":200`) {
		t.Errorf("raw output lost the rest of the line: %s", res.RawOutput)
	}
	if len(res.LiveHosts) == 0 || res.LiveHosts[0].ResponseHeaders == nil {
		t.Errorf("hosts parsed from the unstripped lines: %+v", res.LiveHosts)
	}
}
