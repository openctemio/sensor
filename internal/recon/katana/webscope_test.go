package katana

import (
	"regexp"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// flagValues are the values of every occurrence of a flag.
func flagValues(args []string, flag string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			out = append(out, args[i+1])
		}
	}
	return out
}

// SECURITY: the out-of-scope regexes katana gets match a denied path
// however it is spelled (katana's regexes are Go regexes, as here).
func TestDenyPathRegexMatchesEverySpelling(t *testing.T) {
	ks, err := NewScanner().WithWebScope(&webscope.Scope{DenyPaths: []string{"/admin", "/logout"}})
	if err != nil {
		t.Fatal(err)
	}
	args := ks.(*Scanner).buildArgs("https://app.example.com", nil)
	cos := flagValues(args, "-cos")
	if len(cos) != 2 {
		t.Fatalf("-cos %v", cos)
	}
	res := make([]*regexp.Regexp, len(cos))
	for i, c := range cos {
		res[i] = regexp.MustCompile(c)
	}
	matches := func(u string) bool {
		return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(u) })
	}
	for _, u := range []string{
		"https://app.example.com/admin", "https://app.example.com/admin/users", "https://app.example.com/ADMIN",
		"https://app.example.com/%61dmin", "https://app.example.com/%41DMIN/x", "https://app.example.com//admin",
		"https://app.example.com/%2fadmin", "https://app.example.com/\\admin", "http://app.example.com:8080/logout?next=/",
		"https://app.example.com/administrator", // a prefix: over-blocking is the safe side
	} {
		if !matches(u) {
			t.Errorf("not denied: %s", u)
		}
	}
	for _, u := range []string{"https://app.example.com/", "https://app.example.com/public/admin", "https://app.example.com/login"} {
		if matches(u) {
			t.Errorf("denied: %s", u)
		}
	}
	if !slices.Contains(args, "-dr") || !slices.Equal(flagValues(args, "-fs"), []string{"fqdn"}) {
		t.Fatalf("redirects and the fqdn field scope must stay: %v", args)
	}
}

func TestPathPrefixAndHostRegex(t *testing.T) {
	ks, err := NewScanner().WithWebScope(&webscope.Scope{Hosts: []string{"*.example.com"}, PathPrefixes: []string{"/app/"}})
	if err != nil {
		t.Fatal(err)
	}
	cs := flagValues(ks.(*Scanner).buildArgs("https://www.example.com/app/", nil), "-cs")
	if len(cs) != 1 {
		t.Fatalf("-cs %v", cs)
	}
	re := regexp.MustCompile(cs[0])
	for u, want := range map[string]bool{
		"https://www.example.com/app/":        true,
		"https://example.com/app?x=1":         true,
		"https://www.example.com:8443/app/x":  true,
		"https://www.example.com/application": false,
		"https://www.example.com/":            false,
		"https://example.com.evil.com/app/":   false,
		"https://evil.com/app/":               false,
	} {
		if re.MatchString(u) != want {
			t.Errorf("%s: in scope %v, want %v (%s)", u, !want, want, cs[0])
		}
	}
}

// Form filling submits forms: off unless the scope allows POST.
func TestWebScopeTurnsOffFormFill(t *testing.T) {
	s := NewDeepCrawler()
	s.FollowRedirects = true
	got, err := s.WithWebScope(&webscope.Scope{DenyPaths: []string{"/logout"}})
	if err != nil {
		t.Fatal(err)
	}
	if k := got.(*Scanner); k.FormFill || k.FollowRedirects || k.WebScope == nil {
		t.Fatalf("scanner %+v", k)
	}
	if !s.FormFill || s.WebScope != nil {
		t.Fatal("the original scanner was modified")
	}
	got, _ = s.WithWebScope(&webscope.Scope{Methods: []string{"GET", "POST"}})
	if !got.(*Scanner).FormFill {
		t.Fatal("POST allowed: form filling stays")
	}
	if _, err := s.WithWebScope(&webscope.Scope{DenyPaths: []string{"admin"}}); err == nil {
		t.Fatal("an invalid scope must be refused")
	}
}

// SECURITY: a URL katana reports outside the scope never reaches the
// platform.
func TestResultsFilteredByWebScope(t *testing.T) {
	ks, _ := NewScanner().WithWebScope(&webscope.Scope{DenyPaths: []string{"/admin"}})
	urls := []core.DiscoveredURL{{URL: "https://a.example.com/x"}, {URL: "https://a.example.com/Admin/y"},
		{URL: "https://b.example.com/x"}, {URL: "https://a.example.com/form", Method: "POST"}}
	got := ks.(*Scanner).inWebScope("https://a.example.com", urls)
	if len(got) != 1 || got[0].URL != "https://a.example.com/x" {
		t.Fatalf("kept %+v", got)
	}
}
