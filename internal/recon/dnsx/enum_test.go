package dnsx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
	"github.com/openctemio/sensor/internal/toolrun"
)

// fakeDNSX stands in for dnsx: it records its arguments and the list it was
// given, and prints a fixed answer, including names the real tool would
// never print for the root (a hostile or buggy answer must not get through).
func fakeDNSX(t *testing.T, answer string) (bin, argsFile, listCopy string) {
	t.Helper()
	dir := t.TempDir()
	argsFile, listCopy = filepath.Join(dir, "args"), filepath.Join(dir, "list")
	if err := os.WriteFile(filepath.Join(dir, "answer"), []byte(answer), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"echo \"$@\" > " + argsFile + "\n" +
		"list=\"\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  case \"$1\" in -w) list=\"$2\"; shift ;; esac\n" +
		"  shift\n" +
		"done\n" +
		"cp \"$list\" " + listCopy + "\n" +
		"cat " + filepath.Join(dir, "answer") + "\n"
	bin = filepath.Join(dir, "dnsx")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // a test double
		t.Fatal(err)
	}
	return bin, argsFile, listCopy
}

func writeList(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "labels.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnumBuildsADnsxBruteForceOfTheJobsList(t *testing.T) {
	answer := `{"host":"www.example.com","a":["192.0.2.1"]}
{"host":"mail.example.com","a":["192.0.2.2"]}
{"host":"www.other.org","a":["192.0.2.3"]}
{"host":"example.com","a":["192.0.2.4"]}
{"host":"badexample.com","a":["192.0.2.5"]}
{"host":"x.internal.example.com","a":["192.0.2.6"]}
{"host":"EVIL.example.com.evil.net","a":["192.0.2.7"]}
`
	bin, argsFile, _ := fakeDNSX(t, answer)
	s := NewEnumScanner()
	s.Binary = bin
	rs, err := s.WithWordlist(writeList(t, "www", "mail"))
	if err != nil {
		t.Fatal(err)
	}
	rs, err = rs.(*EnumScanner).WithExcludeHosts([]string{"internal.example.com."})
	if err != nil {
		t.Fatal(err)
	}
	res, err := rs.Scan(context.Background(), "Example.COM.", &core.ReconOptions{InputFile: "/etc/passwd", Resolvers: []string{"192.0.2.53"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res.DNSRecords {
		got = append(got, r.Host)
	}
	// Only names strictly below the root, outside the excluded subtree.
	if want := []string{"www.example.com", "mail.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	raw, _ := os.ReadFile(argsFile) //nolint:gosec // test file
	args := strings.Fields(string(raw))
	for _, want := range []string{"-d", "example.com", "-w", "-rl", "50", "-t", "-auto-wildcard", "-json", "-duc"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v lack %q", args, want)
		}
	}
	// A file of targets never reaches a brute force.
	if slices.Contains(args, "-l") || slices.Contains(args, "/etc/passwd") {
		t.Errorf("args %v carry the input file", args)
	}
	flagcheck.Check(t, helpFile, args)
}

func TestEnumRefusesWithoutAWordlist(t *testing.T) {
	s := NewEnumScanner()
	s.Binary = "/nonexistent/dnsx"
	if _, err := s.Scan(context.Background(), "example.com", nil); !errors.Is(err, ErrNoWordlist) {
		t.Fatalf("err = %v, want ErrNoWordlist (no built-in list)", err)
	}
	if _, err := s.WithWordlist(""); !errors.Is(err, ErrNoWordlist) {
		t.Fatalf("empty path: %v", err)
	}
}

func TestEnumTargetMustBeOneRootDomain(t *testing.T) {
	s, err := NewEnumScanner().WithWordlist(writeList(t, "www"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"", "192.0.2.1", "2001:db8::1", "a.example.com,b.example.com", "http://example.com", "example.com/x", "*.example.com", "localhost", "-bad.example.com", "a b.example.com", "user@example.com"} {
		if _, err := s.Scan(context.Background(), target, nil); err == nil || !strings.Contains(err.Error(), "not a root domain") {
			t.Errorf("target %q: err = %v", target, err)
		}
	}
}

func TestEnumMaxQueriesCutsTheList(t *testing.T) {
	bin, _, listCopy := fakeDNSX(t, `{"host":"a.example.com","a":["192.0.2.1"]}`+"\n")
	s := NewEnumScanner()
	s.Binary = bin
	s.MaxQueries = 3
	rs, _ := s.WithWordlist(writeList(t, "a", "b", "c", "d", "e"))
	if _, err := rs.Scan(context.Background(), "example.com", nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(listCopy) //nolint:gosec // test file
	if string(got) != "a\nb\nc\n" {
		t.Fatalf("dnsx was given %q, want the first 3 labels", got)
	}
}

func TestEnumNothingResolvedIsAnAnswerNotAFailure(t *testing.T) {
	bin, _, _ := fakeDNSX(t, "")
	s := NewEnumScanner()
	s.Binary = bin
	rs, _ := s.WithWordlist(writeList(t, "a"))
	res, err := rs.Scan(context.Background(), "example.com", nil)
	if err != nil || res.Error != "" || len(res.DNSRecords) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestEnumDescriptor(t *testing.T) {
	m := toolrun.MustManifest(EnumToolYAML)
	if m.Name != EnumName || m.Tier != tool.T1 || m.MinimumTier() != tool.T1 {
		t.Fatalf("name=%s tier=%s min=%s", m.Name, m.Tier, m.MinimumTier())
	}
	if _, ok := m.Implementation("enumerate.subdomains@1"); !ok {
		t.Fatal("does not implement enumerate.subdomains@1")
	}
	slot, ok := m.Slot("labels")
	if !ok || slot.Kind != "wordlist" || slot.Purpose != "dns-labels" || slot.Default != "none" {
		t.Fatalf("slot = %+v", slot)
	}
	if (&EnumScanner{}).WordlistSlot() != slot.Slot {
		t.Fatal("the scanner reads another slot than the descriptor declares")
	}
	// The resolver stays passive: a T0 job still runs it.
	if r := toolrun.MustManifest(ToolYAML); r.MinimumTier() != tool.T0 {
		t.Fatalf("dnsx minimum tier = %s, want T0", r.MinimumTier())
	}
	if _, ok := toolrun.MustManifest(ToolYAML).Implementation("enumerate.subdomains@1"); ok {
		t.Fatal("the T0 resolver must not implement the active capability")
	}
}

func TestEnumSettingsRateIsBounded(t *testing.T) {
	rs, err := NewEnumScanner().WithSettings(resolveEnum(t, map[string]any{"rate_limit": 20, "max_queries": 100, "retries": 0}))
	if err != nil {
		t.Fatal(err)
	}
	e := rs.(*EnumScanner)
	if e.RateLimit != 20 || e.MaxQueries != 100 || e.Retries != 1 {
		t.Fatalf("rate=%d max=%d retries=%d", e.RateLimit, e.MaxQueries, e.Retries)
	}
	if _, err := enumSettingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"rate_limit": 500}}); err == nil {
		t.Fatal("a scan must not raise the polite default rate")
	}
	if _, err := enumSettingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"method": "permutations"}}); err == nil {
		t.Fatal("permutations are not implemented by this tool")
	}
}

func resolveEnum(t *testing.T, v map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := enumSettingsSchema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}
