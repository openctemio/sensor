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
	want := []string{"-u", "https://example.com", "-duc", "-jsonl", "-c", "10", "-d", "3", "-rl", "150", "-js-crawl", "-fs", "rdn", "-silent"}
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
