package katana

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func line(t *testing.T, req map[string]any, resp map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"request": req, "response": resp})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseOutput_WebContent(t *testing.T) {
	page := "https://app.example.com/login?next=/a&sid=SECRET#frag"
	data := strings.Join([]string{
		line(t, map[string]any{"method": "GET", "endpoint": "https://app.example.com/login", "tag": "a", "attribute": "href", "source": page},
			map[string]any{"status_code": 200, "headers": map[string]string{"content-type": "Text/HTML; charset=utf-8", "Set-Cookie": "sid=SECRETCOOKIE"},
				"forms": []map[string]any{
					{"method": "POST", "action": "/session?csrf=SECRETCSRF", "parameters": []string{"email", "password", "remember"}},
					{"method": "GET", "action": "javascript:alert(1)", "parameters": []string{"q"}},
					{"action": "https://other.example.net/x", "parameters": []string{"z"}},
				}}),
		line(t, map[string]any{"method": "GET", "endpoint": "https://app.example.com/admin", "tag": "file", "attribute": "robotstxt", "source": "https://app.example.com/robots.txt"},
			map[string]any{"status_code": 403}),
		line(t, map[string]any{"method": "GET", "endpoint": "https://app.example.com/app.js", "tag": "script", "attribute": "src", "source": "https://app.example.com/"},
			map[string]any{"status_code": 200, "headers": map[string]string{"Content-Type": "application/javascript"}}),
		line(t, map[string]any{"method": "GET", "endpoint": "javascript:alert(1)", "tag": "a", "source": "https://app.example.com/"}, map[string]any{"status_code": 200}),
		line(t, map[string]any{"method": "GET", "endpoint": "https://app.example.com/crlf\r\nX: y", "tag": "a"}, map[string]any{"status_code": 200}),
		line(t, map[string]any{"method": "GET", "endpoint": "https://app.example.com/big" + strings.Repeat("a", 1<<20)}, map[string]any{"status_code": 200}),
		line(t, map[string]any{"method": "GET\r\nX", "endpoint": "https://app.example.com/m"}, map[string]any{"status_code": 200}),
		line(t, map[string]any{"method": "GET", "endpoint": "https://app.example.com/ct"},
			map[string]any{"status_code": 200, "headers": map[string]string{"Content-Type": "text/html\r\nX: y"}}),
	}, "\n")
	urls, err := NewScanner().parseOutput([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]core.DiscoveredURL{}
	for _, u := range urls {
		by[u.URL] = u
	}
	if len(urls) != 4 {
		t.Fatalf("urls: %+v", urls)
	}
	login := by["https://app.example.com/login"]
	if login.ContentType != "text/html" || login.Parent != "https://app.example.com/login?next=&sid=" || login.Source != "a" {
		t.Errorf("login: %+v", login)
	}
	if len(login.Forms) != 3 {
		t.Fatalf("forms: %+v", login.Forms)
	}
	f := login.Forms[0]
	if f.Method != "POST" || f.Action != "https://app.example.com/session" || !f.PasswordField || len(f.Params) != 3 || f.Params[1].Name != "password" || f.Params[1].Location != "form" {
		t.Errorf("login form: %+v", f)
	}
	if f := login.Forms[1]; f.Action != "" || f.PasswordField {
		t.Errorf("javascript: action: %+v", f)
	}
	if f := login.Forms[2]; f.Action != "https://other.example.net/x" || f.Method != "GET" {
		t.Errorf("cross-origin form keeps its action for the receiver to refuse: %+v", f)
	}
	if kf := by["https://app.example.com/admin"]; kf.Source != "robotstxt" || kf.Parent != "https://app.example.com/robots.txt" {
		t.Errorf("known file: %+v", kf)
	}
	if js := by["https://app.example.com/app.js"]; js.Source != "script" || js.ContentType != "application/javascript" || js.Type != "script" {
		t.Errorf("script: %+v", js)
	}
	if by["https://app.example.com/ct"].ContentType != "" {
		t.Errorf("hostile content type kept: %+v", by["https://app.example.com/ct"])
	}
	out, _ := json.Marshal(urls)
	for _, leak := range []string{"SECRET", "frag", "alert(1)"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("%q reached the output: %s", leak, out)
		}
	}
}

func TestBuildArgs_KnownFilesAndForms(t *testing.T) {
	s := NewScanner()
	got := s.buildArgs("https://example.com", nil)
	if i := slices.Index(got, "-kf"); i < 0 || got[i+1] != "all" || !slices.Contains(got, "-fx") {
		t.Errorf("default args: %q", got)
	}
	flagcheck.Check(t, helpFile, got)

	s.FormExtraction, s.KnownFiles = false, ""
	got = s.buildArgs("https://example.com", nil)
	if slices.Contains(got, "-kf") || slices.Contains(got, "-fx") {
		t.Errorf("switched off: %q", got)
	}
	if b := NewBasicCrawler().buildArgs("https://example.com", nil); slices.Contains(b, "-kf") {
		t.Errorf("basic crawler (depth 2) asks for known files: %q", b)
	}
}

func TestKnownFilesFollowTheWebScope(t *testing.T) {
	cases := []struct {
		name   string
		ws     *webscope.Scope
		target string
		input  string
		want   string
	}{
		{"no scope", nil, "https://example.com", "", "all"},
		{"open scope", &webscope.Scope{}, "https://example.com", "", "all"},
		{"prefix excludes both", &webscope.Scope{PathPrefixes: []string{"/app"}}, "https://example.com/app", "", ""},
		{"deny robots", &webscope.Scope{DenyPaths: []string{"/robots.txt"}}, "https://example.com", "", "sitemapxml"},
		{"deny sitemap", &webscope.Scope{DenyPaths: []string{"/sitemap"}}, "https://example.com", "", "robotstxt"},
		{"deny root", &webscope.Scope{DenyPaths: []string{"/"}}, "https://example.com", "", ""},
		{"list input with path rules", &webscope.Scope{DenyPaths: []string{"/admin"}}, "", "hosts.txt", ""},
		{"list input without path rules", &webscope.Scope{Hosts: []string{"example.com"}}, "", "hosts.txt", "all"},
	}
	for _, c := range cases {
		s := NewScanner()
		s.WebScope = c.ws
		var opts *core.ReconOptions
		if c.input != "" {
			opts = &core.ReconOptions{InputFile: c.input}
		}
		if got := s.knownFilesArg(c.target, opts); got != c.want {
			t.Errorf("%s: -kf %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSourceLabel(t *testing.T) {
	for r, want := range map[KatanaRequest]string{
		{Tag: "file", Attribute: "sitemapxml", Source: "https://x/sitemap.xml"}: "sitemapxml",
		{Tag: "a", Attribute: "href", Source: "https://x/robots-js/"}:           "a",
		{Tag: "js", Attribute: "regex"}:                                         "js",
		{}:                                                                      "crawl",
	} {
		if got := sourceLabel(r); got != want {
			t.Errorf("%+v: %q want %q", r, got, want)
		}
	}
}
