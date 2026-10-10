package katana

import (
	"regexp"
	"testing"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
)

// A path-limited job crawls only under the limit's prefix (the in-scope
// regex katana gets); the forwarder enforces it in any case.
func TestWithScopeLimitsCrawlsUnderThePrefix(t *testing.T) {
	ks, err := NewScanner().WithScopeLimits(scopelimit.NewSet([]scopelimit.Limit{{Host: "app.example.com", Ports: "443", PathPrefix: "/api"}}))
	if err != nil {
		t.Fatal(err)
	}
	s := ks.(*Scanner)
	if s.WebScope == nil || len(s.WebScope.PathPrefixes) != 1 || s.FollowRedirects {
		t.Fatalf("scanner %+v", s)
	}
	in := flagValues(s.buildArgs("https://app.example.com/api/", nil), "-cs")
	if len(in) != 1 {
		t.Fatalf("in-scope flags %v", in)
	}
	re := regexp.MustCompile(in[0])
	for u, want := range map[string]bool{"https://app.example.com/api/x": true, "https://app.example.com/admin": false, "https://app.example.com/apiadmin": false} {
		if re.MatchString(u) != want {
			t.Errorf("%s: match %v", u, !want)
		}
	}
	// A port-only limit leaves the crawl as it was.
	ps, _ := NewScanner().WithScopeLimits(scopelimit.NewSet([]scopelimit.Limit{{Host: "app.example.com", Ports: "8443"}}))
	if ps.(*Scanner).WebScope != nil {
		t.Fatal("a port-only limit set a web scope")
	}
}
