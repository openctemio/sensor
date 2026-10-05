package resolv

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSystem(t *testing.T) {
	p := writeFile(t, `# Docker embedded DNS
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
	got := System(p)
	want := []string{"127.0.0.11", "[2001:db8::53]:53", "10.0.0.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("System = %q, want %q", got, want)
	}
	if got := System(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatalf("missing file: %q, want none", got)
	}
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// The operator's list wins over resolv.conf; unset, resolv.conf is used.
func TestSensor(t *testing.T) {
	old := ResolvConfPath
	ResolvConfPath = writeFile(t, "nameserver 10.1.1.1\n")
	t.Cleanup(func() { ResolvConfPath = old })

	got, err := Sensor(env(nil))
	if err != nil || !slices.Equal(got, []string{"10.1.1.1"}) {
		t.Fatalf("resolv.conf: %q %v", got, err)
	}
	got, err = Sensor(env(map[string]string{EnvResolvers: " 192.0.2.53, 192.0.2.54:5353 ,2001:db8::1,[2001:db8::2]:5353"}))
	want := []string{"192.0.2.53", "192.0.2.54:5353", "[2001:db8::1]:53", "[2001:db8::2]:5353"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("env: %q %v, want %q", got, err, want)
	}
	if got, err := Sensor(env(map[string]string{EnvResolvers: "  "})); err != nil || !slices.Equal(got, []string{"10.1.1.1"}) {
		t.Fatalf("blank env: %q %v", got, err)
	}
}

// SECURITY (negative): only IP literals; nothing that could become a flag,
// a file or a name that itself needs resolving. An invalid value is an
// error, never silently replaced by another list.
func TestSensorRefusesInvalidList(t *testing.T) {
	for _, v := range []string{
		"dns.example.com", "-r", "/etc/hosts", "192.0.2.1:0", "192.0.2.1:99999",
		"0.0.0.0", "192.0.2.1;rm", "192.0.2.1 -o x", "[::]:53",
	} {
		if got, err := Sensor(env(map[string]string{EnvResolvers: v})); err == nil {
			t.Errorf("%q accepted as %q", v, got)
		}
	}
	many := ""
	for i := 0; i <= MaxEnv; i++ {
		many += "192.0.2.1,"
	}
	if _, err := Parse(many); err == nil {
		t.Error("more than MaxEnv resolvers accepted")
	}
}
