package nuclei

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/sensor/internal/egressenv"
)

func stubLookup(t *testing.T, table map[string]string) {
	t.Helper()
	old := lookupHost
	lookupHost = func(_ context.Context, host string) ([]netip.Addr, error) {
		a, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	t.Cleanup(func() { lookupHost = old })
}

// An unconfined custom run gets -lna unless its own targets are local.
func TestCustomLocalNetworkArgs(t *testing.T) {
	t.Setenv(egressenv.EnvProxy, "")
	stubLookup(t, map[string]string{"public.example.com": "203.0.113.7", "intranet.example.com": "10.1.2.3"})
	s := NewScanner()
	ctx := context.Background()
	cases := map[string]struct {
		target string
		want   bool
	}{
		"public name":         {"https://public.example.com/app", true},
		"public address":      {"203.0.113.7:8443", true},
		"unresolvable":        {"nx.example.com", true},
		"private name":        {"https://intranet.example.com", false},
		"private address":     {"192.168.1.10", false},
		"loopback":            {"http://127.0.0.1:8080", false},
		"metadata":            {"169.254.169.254", false},
		"localhost":           {"http://localhost:9000", false},
		"ipv6 loopback":       {"http://[::1]:80/", false},
		"shared address":      {"100.64.0.1", false},
		"private range":       {"10.0.0.0/24", false},
		"mapped private ipv6": {"::ffff:10.0.0.1", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := slices.Contains(s.customLocalNetworkArgs(ctx, c.target, ""), "-lna")
			if got != c.want {
				t.Fatalf("-lna = %v, want %v", got, c.want)
			}
		})
	}

	// A list with one internal target is an internal scan.
	list := filepath.Join(t.TempDir(), "targets")
	if err := os.WriteFile(list, []byte("https://public.example.com\nintranet.example.com:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(s.customLocalNetworkArgs(ctx, "", list), "-lna") {
		t.Fatal("-lna on a list with an internal target")
	}

	// A confined task's forwarder already restricts it.
	t.Setenv(egressenv.EnvProxy, "http://127.0.0.1:1080")
	if args := s.customLocalNetworkArgs(ctx, "https://public.example.com", ""); len(args) != 0 {
		t.Fatalf("confined run got %v", args)
	}
}

func TestCustomLimits(t *testing.T) {
	s := NewScanner()
	s.Timeout = 30 * time.Minute
	l := s.customLimits()
	if l.CPUSeconds != 3600 {
		t.Fatalf("cpu seconds = %d, want 3600", l.CPUSeconds)
	}
	if l.MemoryBytes == 0 || l.Processes == 0 {
		t.Fatalf("sandbox defaults dropped: %+v", l)
	}
}
