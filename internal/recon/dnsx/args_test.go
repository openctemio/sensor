package dnsx

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

const helpFile = "dnsx-1.3.1.help"

func TestBuildArgs_Default(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	want := []string{"-l", "example.com", "-duc", "-json", "-t", "100", "-retry", "2", "-a", "-aaaa", "-cname", "-silent"}
	if !slices.Equal(got, want) {
		t.Fatalf("args = %q\nwant   %q", got, want)
	}
	flagcheck.Check(t, helpFile, got)
}

// A single target must not use -d: that is dnsx's brute-force input and it
// exits with "missing wordlist" without -w.
func TestBuildArgs_SingleTargetIsList(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	if slices.Contains(got, "-d") {
		t.Fatalf("single target uses -d: %q", got)
	}
}

func TestBuildArgs_EveryOptionIsDefined(t *testing.T) {
	s := NewFullRecordScanner()
	s.RateLimit = 50
	s.Resolvers = []string{"1.1.1.1"}
	s.ResponseOnly = true
	s.RespectWildcard = true
	s.OutputCDN = true
	s.OutputASN = true
	s.OutputFile = "/tmp/out.json"
	got := s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/in.txt"})
	flagcheck.Check(t, helpFile, got)
	if !slices.Contains(got, "-auto-wildcard") {
		t.Errorf("RespectWildcard did not add -auto-wildcard: %q", got)
	}

	s = NewScanner()
	s.RecordTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "CAA"}
	flagcheck.Check(t, helpFile, s.buildArgs("example.com", nil))
}
