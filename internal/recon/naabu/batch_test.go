package naabu

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func TestAttributorMapsRecordsToTargets(t *testing.T) {
	a := newAttributor([]string{"WWW.Example.com.", "192.0.2.10", "198.51.100.0/24", "2001:db8::/120"})
	cases := []struct {
		p    core.OpenPort
		want string
		ok   bool
	}{
		{core.OpenPort{Host: "www.example.com", IP: "203.0.113.5", Port: 443}, "WWW.Example.com.", true},
		{core.OpenPort{Host: "192.0.2.10", IP: "192.0.2.10", Port: 22}, "192.0.2.10", true},
		{core.OpenPort{Host: "::ffff:192.0.2.10", Port: 22}, "192.0.2.10", true},
		{core.OpenPort{Host: "198.51.100.77", IP: "198.51.100.77", Port: 80}, "198.51.100.0/24", true},
		{core.OpenPort{Host: "2001:db8::5", Port: 80}, "2001:db8::/120", true},
		// Not one of the targets: dropped, never attributed to another.
		{core.OpenPort{Host: "evil.example", IP: "203.0.113.9", Port: 80}, "", false},
		{core.OpenPort{Host: "", IP: "", Port: 80}, "", false},
	}
	for _, c := range cases {
		got, ok := a.target(c.p)
		if got != c.want || ok != c.ok {
			t.Errorf("%+v -> %q %v, want %q %v", c.p, got, ok, c.want, c.ok)
		}
	}
}

func TestBatchArgsUseTheListAndWorkers(t *testing.T) {
	s := NewScanner()
	args := s.buildArgs("", &core.ReconOptions{InputFile: "/tmp/list.txt", Threads: 50})
	if i := slices.Index(args, "-l"); i < 0 || args[i+1] != "/tmp/list.txt" {
		t.Fatalf("no -l: %v", args)
	}
	if slices.Contains(args, "-host") {
		t.Fatalf("-host with a list: %v", args)
	}
	if i := slices.Index(args, "-c"); i < 0 || args[i+1] != "50" {
		t.Fatalf("no -c 50: %v", args)
	}
	// Without a job concurrency naabu keeps its own default.
	if slices.Contains(s.buildArgs("a.example", &core.ReconOptions{}), "-c") {
		t.Fatal("-c without a concurrency")
	}
}
