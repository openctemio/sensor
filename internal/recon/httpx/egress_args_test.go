package httpx

import (
	"slices"
	"testing"

	"github.com/openctemio/sensor/internal/egressenv"
)

// A confined task (api RFC-060) reaches the network only through its
// forwarder's relay: its proxy flag names the relay.
func TestConfinedTaskUsesTheRelay(t *testing.T) {
	before := NewScanner().buildArgs("example.com", nil)
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:1080")
	args := NewScanner().buildArgs("example.com", nil)
	if i := slices.Index(args, "-proxy"); i < 0 || i+1 >= len(args) || args[i+1] != "http://127.0.0.1:1080" {
		t.Fatalf("confined args %q: want -proxy http://127.0.0.1:1080", args)
	}
	if i := slices.Index(before, "-proxy"); i >= 0 && before[i+1] == "http://127.0.0.1:1080" {
		t.Fatalf("unconfined args already name the relay: %q", before)
	}
}

// JARM's probes dial the host directly, not through -proxy: a confined task
// does not ask for them (each target waited about 30 s for nothing, and
// through a plain proxy they would bypass it). Unconfined, JARM stays on.
func TestProxiedTaskSkipsJARM(t *testing.T) {
	t.Setenv(egressenv.EnvProxy, "")
	if args := NewScanner().buildArgs("example.com", nil); !slices.Contains(args, "-jarm") {
		t.Fatalf("unconfined args lack -jarm: %q", args)
	}
	s := NewScanner()
	s.Proxy = "http://proxy.internal:3128"
	if args := s.buildArgs("example.com", nil); slices.Contains(args, "-jarm") {
		t.Fatalf("args with an explicit proxy ask for -jarm: %q", args)
	}
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:1080")
	if args := NewScanner().buildArgs("example.com", nil); slices.Contains(args, "-jarm") {
		t.Fatalf("confined args ask for -jarm: %q", args)
	}
}
