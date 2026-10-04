package dnsx

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func withResolvConf(t *testing.T, content string) {
	t.Helper()
	old := resolvConfPath
	resolvConfPath = writeFile(t, "resolv.conf", content)
	t.Cleanup(func() { resolvConfPath = old })
}

func TestSystemResolvers(t *testing.T) {
	p := writeFile(t, "resolv.conf", `# Docker embedded DNS
search svc.cluster.local
nameserver 127.0.0.11
nameserver 127.0.0.11
nameserver fe80::1%eth0
nameserver not-an-ip
nameserver 0.0.0.0
nameserver 2001:db8::53
options ndots:0
nameserver 10.0.0.2
nameserver 10.0.0.3
`)
	got := systemResolvers(p)
	want := []string{"127.0.0.11", "[2001:db8::53]:53", "10.0.0.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("systemResolvers = %q, want %q", got, want)
	}
	if got := systemResolvers(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatalf("missing file: %q, want none", got)
	}
}

func TestInputHosts(t *testing.T) {
	got, ok := inputHosts(" Web.Internal. ,example.com,web.internal,", nil)
	if !ok || !slices.Equal(got, []string{"web.internal", "example.com"}) {
		t.Fatalf("target list = %q %v", got, ok)
	}
	f := writeFile(t, "in.txt", "a.example\n\nB.example\r\na.example\n")
	got, ok = inputHosts("ignored", &core.ReconOptions{InputFile: f})
	if !ok || !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Fatalf("input file = %q %v", got, ok)
	}
	if _, ok := inputHosts("", &core.ReconOptions{InputFile: filepath.Join(t.TempDir(), "missing")}); ok {
		t.Fatal("an unreadable input file must skip the fallback")
	}
}

func TestUnresolvedHosts(t *testing.T) {
	stdout := []byte(`{"host":"Example.com","a":["93.184.215.14"]}
not json
{"host":"cdn.example.com.","cname":["x.cdn.net"]}
`)
	got := unresolvedHosts([]string{"example.com", "web.internal", "cdn.example.com"}, stdout)
	if !slices.Equal(got, []string{"web.internal"}) {
		t.Fatalf("unresolved = %q", got)
	}
}

func TestFallbackPlan(t *testing.T) {
	withResolvConf(t, "nameserver 127.0.0.11\n")
	stdout := []byte(`{"host":"example.com","a":["93.184.215.14"]}`)

	s := NewScanner()
	s.OutputFile = "/tmp/out.json"
	fb, fbOpts, cleanup, ok := s.fallbackPlan("example.com,web.internal", &core.ReconOptions{Threads: 5}, stdout)
	if !ok {
		t.Fatal("want a fallback run for web.internal")
	}
	defer cleanup()
	data, err := os.ReadFile(fbOpts.InputFile)
	if err != nil || strings.TrimSpace(string(data)) != "web.internal" {
		t.Fatalf("fallback input = %q, %v; want only the unresolved host", data, err)
	}
	args := fb.buildArgs("", fbOpts)
	flagcheck.Check(t, helpFile, args)
	if i := slices.Index(args, "-r"); i < 0 || args[i+1] != "127.0.0.11" {
		t.Fatalf("fallback args %q: want -r 127.0.0.11", args)
	}
	if slices.Contains(args, "-o") {
		t.Fatalf("fallback args %q must not overwrite the output file", args)
	}
	if i := slices.Index(args, "-t"); i < 0 || args[i+1] != "5" {
		t.Fatalf("fallback args %q: the job's threads must carry over", args)
	}
	if s.OutputFile != "/tmp/out.json" || len(s.Resolvers) != 0 {
		t.Fatal("the fallback must not change the scanner it was planned from")
	}
	cleanup()
	if _, err := os.Stat(fbOpts.InputFile); !os.IsNotExist(err) {
		t.Fatal("cleanup must remove the fallback input file")
	}
}

func TestFallbackPlan_None(t *testing.T) {
	withResolvConf(t, "nameserver 127.0.0.11\n")
	all := []byte(`{"host":"example.com","a":["1.2.3.4"]}`)

	cases := map[string]func() (*Scanner, string, *core.ReconOptions, []byte){
		"everything resolved": func() (*Scanner, string, *core.ReconOptions, []byte) {
			return NewScanner(), "example.com", nil, all
		},
		"extra args pick resolvers": func() (*Scanner, string, *core.ReconOptions, []byte) {
			return NewScanner(), "web.internal", &core.ReconOptions{ExtraArgs: []string{"-r", "9.9.9.9"}}, nil
		},
		"first run already used the system resolvers": func() (*Scanner, string, *core.ReconOptions, []byte) {
			s := NewScanner()
			s.Resolvers = []string{"127.0.0.11"}
			return s, "web.internal", nil, nil
		},
	}
	for name, mk := range cases {
		s, target, opts, stdout := mk()
		if _, _, _, ok := s.fallbackPlan(target, opts, stdout); ok {
			t.Errorf("%s: want no fallback run", name)
		}
	}

	withResolvConf(t, "# no nameserver\n")
	if _, _, _, ok := NewScanner().fallbackPlan("web.internal", nil, nil); ok {
		t.Error("no system resolver: want no fallback run")
	}
}

// Scan end to end with a stand-in dnsx: it answers public names whatever the
// resolver, and the internal name only through the system resolver, as the
// real dnsx does on a Docker network.
func TestScan_SystemResolverFallback(t *testing.T) {
	withResolvConf(t, "nameserver 127.0.0.11\n")
	bin := writeFile(t, "dnsx", `#!/bin/sh
resolver=""; list=""
while [ $# -gt 0 ]; do
  case "$1" in
    -r) resolver="$2"; shift ;;
    -l) list="$2"; shift ;;
  esac
  shift
done
if [ -f "$list" ]; then hosts=$(cat "$list"); else hosts=$(echo "$list" | tr ',' ' '); fi
for h in $hosts; do
  case "$h" in
    example.com) echo '{"host":"example.com","resolver":["1.1.1.1:53"],"a":["93.184.215.14"]}' ;;
    web.internal) [ "$resolver" = "127.0.0.11" ] && echo '{"host":"web.internal","resolver":["127.0.0.11:53"],"a":["172.23.0.2"]}' ;;
  esac
done
exit 0
`)
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	s := NewScanner()
	s.Binary = bin
	res, err := s.Scan(context.Background(), "example.com,web.internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range res.DNSRecords {
		got[r.Host] = strings.Join(r.Values, ",") + "@" + r.Resolver
	}
	if got["example.com"] != "93.184.215.14@1.1.1.1:53" {
		t.Errorf("example.com = %q, want its public answer", got["example.com"])
	}
	if got["web.internal"] != "172.23.0.2@127.0.0.11:53" {
		t.Errorf("web.internal = %q, want the system resolver answer", got["web.internal"])
	}
}
