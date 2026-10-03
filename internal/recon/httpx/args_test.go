package httpx

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

const helpFile = "httpx-1.12.0.help"

func TestBuildArgs_DefaultIsDefined(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	if got[0] != "-u" || got[1] != "example.com" || !slices.Contains(got, "-duc") || !slices.Contains(got, "-json") {
		t.Fatalf("args = %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}

// httpx does not follow redirects by default and has no
// -no-follow-redirects flag.
func TestBuildArgs_NoFollowRedirects(t *testing.T) {
	s := NewScanner()
	s.FollowRedirects = false
	got := s.buildArgs("example.com", nil)
	if slices.Contains(got, "-follow-redirects") {
		t.Errorf("follows redirects: %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}

func TestBuildArgs_EveryOptionIsDefined(t *testing.T) {
	s := NewScanner()
	s.Proxy = "http://127.0.0.1:8080"
	s.Headers = []string{"X-Test: 1"}
	s.Method = "GET"
	s.CDN = true
	s.Favicon = true
	s.Jarm = true
	s.ASN = true
	s.IP = true
	s.TLSProbe = true
	s.TLSGrab = true
	s.MatchCodes = []int{200}
	s.FilterCodes = []int{404}
	s.MatchString = "ok"
	s.FilterString = "nope"
	s.OutputFile = "/tmp/out.json"
	flagcheck.Check(t, helpFile, s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/in.txt"}))
}
