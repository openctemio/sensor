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

// The default probe keeps what it learns about the server (TLS leaf,
// favicon, JARM, CDN) and follows redirects on the same host only. ASN is
// not asked: httpx sends every address to a third-party API for it.
func TestBuildArgs_DefaultServerFieldsAndSameHostRedirects(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	for _, f := range []string{"-tls-grab", "-favicon", "-jarm", "-cdn", "-follow-host-redirects"} {
		if !slices.Contains(got, f) {
			t.Errorf("default args lack %s: %q", f, got)
		}
	}
	for _, f := range []string{"-follow-redirects", "-asn"} {
		if slices.Contains(got, f) {
			t.Errorf("default args contain %s: %q", f, got)
		}
	}
	flagcheck.Check(t, helpFile, got)

	s := NewScanner()
	s.FollowRedirects = true
	got = s.buildArgs("example.com", nil)
	if !slices.Contains(got, "-follow-redirects") || slices.Contains(got, "-follow-host-redirects") {
		t.Errorf("explicit any-host redirects: %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}
