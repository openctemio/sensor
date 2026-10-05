package katana

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

const helpFile = "katana-1.7.0.help"

func TestBuildArgs_Default(t *testing.T) {
	got := NewScanner().buildArgs("https://example.com", nil)
	want := []string{"-u", "https://example.com", "-duc", "-jsonl", "-c", "10", "-d", "3", "-rl", "150", "-js-crawl", "-fs", "fqdn", "-dr", "-silent"}
	if !slices.Equal(got, want) {
		t.Fatalf("args = %q\nwant   %q", got, want)
	}
	flagcheck.Check(t, helpFile, got)
}

// dn/rdn/fqdn are field-scope (-fs) values; -cs is a regex and "-cs rdn"
// kept only URLs containing "rdn".
func TestBuildArgs_ScopeIsFieldScope(t *testing.T) {
	s := NewScanner()
	s.Scope = ScopeFQDN
	got := s.buildArgs("https://example.com", nil)
	if slices.Contains(got, "-cs") {
		t.Errorf("scope uses -cs: %q", got)
	}
	if i := slices.Index(got, "-fs"); i < 0 || got[i+1] != "fqdn" {
		t.Errorf("scope not passed as -fs fqdn: %q", got)
	}
	s.FieldScope = `(example)\.com`
	got = s.buildArgs("https://example.com", nil)
	if i := slices.Index(got, "-fs"); i < 0 || got[i+1] != s.FieldScope || slices.Index(got[i+1:], "-fs") >= 0 {
		t.Errorf("custom field scope: %q", got)
	}
}

// -rd is in seconds.
func TestBuildArgs_DelayInSeconds(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Second: "1", 1500 * time.Millisecond: "2", 200 * time.Millisecond: "1", 5 * time.Second: "5"} {
		s := NewScanner()
		s.Delay = d
		got := s.buildArgs("https://example.com", nil)
		if i := slices.Index(got, "-rd"); i < 0 || got[i+1] != want {
			t.Errorf("delay %v: args %q, want -rd %s", d, got, want)
		}
	}
}

func TestBuildArgs_EveryOptionIsDefined(t *testing.T) {
	s := NewDeepCrawler()
	s.RateLimitMinute = 600
	s.Delay = time.Second
	s.FilterExtension = []string{"png"}
	s.MatchExtension = []string{"php"}
	s.FilterRegex = "logout"
	s.MatchRegex = "api"
	s.Headless = true
	s.HeadlessOptions = "--no-sandbox"
	s.Proxy = "http://127.0.0.1:8080"
	s.StoreResponse = true
	s.StoreResponseDir = "/tmp/resp"
	s.OutputFile = "/tmp/out.jsonl"
	s.OutputAll = true
	got := s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/in.txt"})
	flagcheck.Check(t, helpFile, got, "--no-sandbox") // a value of -headless-options
	if !slices.Contains(got, "-aff") {
		t.Errorf("FormFill did not add -aff: %q", got)
	}
}

// The default crawl stays on the target host: katana gets -fs fqdn, and any
// URL on another host is dropped from the results anyway.
func TestSameHostURLs(t *testing.T) {
	if got := NewScanner().buildArgs("https://example.com", nil); slices.Index(got, "rdn") >= 0 {
		t.Errorf("default crawls the registrable domain: %q", got)
	}
	urls := []core.DiscoveredURL{
		{URL: "https://example.com/a"},
		{URL: "https://EXAMPLE.com.:443/b"},
		{URL: "https://victim.example.org/steal"},
		{URL: "https://sub.example.com/c"},
		{URL: "not a url ::"},
	}
	got := sameHostURLs("https://example.com", append([]core.DiscoveredURL(nil), urls...))
	if len(got) != 2 || got[0].URL != "https://example.com/a" || got[1].URL != "https://EXAMPLE.com.:443/b" {
		t.Errorf("kept %+v", got)
	}
	if got := sameHostURLs("example.com", append([]core.DiscoveredURL(nil), urls...)); len(got) != 2 {
		t.Errorf("bare host target kept %d", len(got))
	}
	if got := sameHostURLs("", append([]core.DiscoveredURL(nil), urls...)); len(got) != len(urls) {
		t.Errorf("no target host: kept %d, want all", len(got))
	}
}

// SECURITY (research/22b S8, negative): katana follows no redirect by
// default (-dr). Measured on katana v1.7.0 with two scratch nginx hosts:
// with -fs fqdn alone, an in-scope link that redirected to the second host
// was fetched there; with -dr it was not. Dropping off-host URLs from the
// results afterwards does not undo the request.
func TestBuildArgs_NoRedirects(t *testing.T) {
	got := NewScanner().buildArgs("https://example.com", nil)
	if !slices.Contains(got, "-dr") {
		t.Errorf("redirects followed: %q", got)
	}
	flagcheck.Check(t, helpFile, got)
	s := NewScanner()
	s.FollowRedirects = true
	if slices.Contains(s.buildArgs("https://example.com", nil), "-dr") {
		t.Error("FollowRedirects set but -dr passed")
	}
}
