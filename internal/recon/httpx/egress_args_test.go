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
