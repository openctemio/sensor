package naabu

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

const helpFile = "naabu-2.6.1.help"

func TestBuildArgs_Default(t *testing.T) {
	got := NewScanner().buildArgs("example.com", nil)
	want := []string{"-host", "example.com", "-duc", "-json", "-top-ports", "100", "-rate", "1000", "-retries", "3", "-s", "c", "-sr", "-silent"}
	if !slices.Equal(got, want) {
		t.Fatalf("args = %q\nwant   %q", got, want)
	}
	flagcheck.Check(t, helpFile, got)
}

// A bare "-c" is naabu's worker-count flag: it took "-silent" as its value
// and every default scan failed.
func TestBuildArgs_ScanTypeIsAValue(t *testing.T) {
	for _, st := range []ScanType{ScanTypeConnect, ScanTypeSYN} {
		s := NewScanner()
		s.ScanType = st
		got := s.buildArgs("example.com", nil)
		i := slices.Index(got, "-s")
		if i < 0 || i+1 >= len(got) || got[i+1] != string(st) {
			t.Errorf("scan type %q: args %q", st, got)
		}
		if slices.Contains(got, "-c") {
			t.Errorf("scan type %q emits bare -c: %q", st, got)
		}
	}
}

func TestBuildArgs_EveryOptionIsDefined(t *testing.T) {
	s := NewFullScanner()
	s.ExcludePorts = "22"
	s.Interface = "eth0"
	s.SourceIP = "10.0.0.1:4444"
	s.Resolvers = []string{"1.1.1.1"}
	s.SkipHostDiscovery = true
	s.Ping = true
	s.ServiceVersion = true
	s.OutputFile = "/tmp/out.json"
	s.TopPorts = 10
	got := s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/in.txt"})
	// "-" is the value of -p (all ports), not a flag.
	flagcheck.Check(t, helpFile, got, "-")
	if !slices.Contains(got, "-sV") {
		t.Errorf("ServiceVersion did not add -sV: %q", got)
	}

	for _, ports := range []string{"top-1000", "80,443"} {
		s := NewScanner()
		s.Ports = ports
		flagcheck.Check(t, helpFile, s.buildArgs("example.com", nil))
	}
}

// naabu resolves names through its built-in public resolvers unless told to
// fall back to the system one: a host only the sensor's network can resolve
// (an internal zone, a Docker service name) gave "no valid ipv4 or ipv6
// targets" and the port scan failed. The fallback stays with custom resolvers.
func TestBuildArgs_SystemResolverFallback(t *testing.T) {
	for _, resolvers := range [][]string{nil, {"10.0.0.53"}} {
		s := NewScanner()
		s.Resolvers = resolvers
		got := s.buildArgs("web.internal", nil)
		if !slices.Contains(got, "-sr") {
			t.Errorf("resolvers %q: no -sr in %q", resolvers, got)
		}
		flagcheck.Check(t, helpFile, got)
	}
}
