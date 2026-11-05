package subfinder

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWithCredentialsWritesThePrivateProviderConfig(t *testing.T) {
	dir := t.TempDir()
	base := &Scanner{}
	keys := map[string]string{
		"securitytrails": "st-key-0001",
		"censys":         "token-0001:org-12345678",
		// A value that tries to add a source or a line is refused by the
		// registry's rules (visible ASCII only) and never written.
		"shodan": "x\"\nvirustotal: [stolen]",
		"empty":  "",
	}
	var logged []string
	rs, err := base.WithCredentials(dir, keys, func(msg string, _ ...any) { logged = append(logged, msg) })
	if err != nil {
		t.Fatal(err)
	}
	s := rs.(*Scanner)
	if base.providerConfig != "" {
		t.Fatal("WithCredentials changed the shared scanner")
	}
	path := filepath.Join(dir, providerConfigName)
	if s.providerConfig != path {
		t.Fatalf("provider config %q", s.providerConfig)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", fi.Mode(), err)
	}
	raw, _ := os.ReadFile(path)
	var cfg map[string][]string
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg) != 2 || cfg["securitytrails"][0] != "st-key-0001" || cfg["censys"][0] != "token-0001:org-12345678" ||
		cfg["shodan"] != nil || cfg["virustotal"] != nil {
		t.Fatalf("provider config %v", cfg)
	}
	// The keys are in the file only: never on the command line.
	args := s.buildArgs("example.com", nil)
	if i := slices.Index(args, "-pc"); i < 0 || args[i+1] != path || !slices.Contains(args, "-stats") {
		t.Fatalf("args %v", args)
	}
	for _, v := range keys {
		if v != "" && strings.Contains(strings.Join(args, " "), v) {
			t.Fatalf("a key is on the command line: %v", args)
		}
	}
	// A second task's file is never the first one's.
	if _, err := base.WithCredentials(dir, nil, nil); err == nil {
		t.Fatal("an existing provider config was overwritten")
	}
	// No keys: still a file of its own (never the host user's default).
	rs, err = base.WithCredentials(t.TempDir(), nil, nil)
	if err != nil || rs.(*Scanner).providerConfig == "" {
		t.Fatalf("no keys: %v", err)
	}
	if _, err := base.WithCredentials("", keys, nil); err == nil {
		t.Fatal("no task directory accepted")
	}
	// Without WithCredentials (the direct path) nothing changes.
	if slices.Contains(base.buildArgs("example.com", nil), "-pc") {
		t.Fatal("-pc without a task")
	}
}

const statsOutput = `[INF] Enumerating subdomains for example.com

 Source               Duration      Results   Requests     Errors
────────────────────────────────────────────────────────────────────
 crtsh                1.2s                12          1          0
 securitytrails       830ms               40          2          0
 shodan               91ms                 0          1          1

 The following sources were included but skipped...

 virustotal
`

func TestStatsReachTheTaskLog(t *testing.T) {
	got := parseStats([]byte(statsOutput))
	if len(got) != 3 || got[1] != (SourceStat{Source: "securitytrails", Results: 40, Requests: 2, Errors: 0}) ||
		got[2].Source != "shodan" || got[2].Errors != 1 {
		t.Fatalf("stats %+v", got)
	}
	if parseStats([]byte("no table here\n 1 2 3 4 5\n")) != nil {
		t.Fatal("parsed lines outside the table")
	}
	var msgs []string
	s := &Scanner{statsLog: func(msg string, args ...any) { msgs = append(msgs, msg+" "+args[1].(string)) }}
	s.logStats([]byte(statsOutput))
	if len(msgs) != 3 || !strings.Contains(msgs[2], "failed") || !strings.HasSuffix(msgs[2], "shodan") || strings.Contains(msgs[1], "failed") {
		t.Fatalf("log %v", msgs)
	}
}

// A key whose host part points subfinder anywhere but the source's own
// service is dropped (and logged), the rest of the file is kept.
func TestProviderConfigRefusesForeignEndpoints(t *testing.T) {
	const k = "abcdef0123456789"
	keys := map[string]string{
		"intelx":         "10.0.0.5:" + k,
		"zoomeyeapi":     "zoomeye.ai.evil.com:" + k,
		"redhuntlabs":    "https://169.254.169.254/latest:" + k,
		"securitytrails": "st-key-0001",
	}
	var refused []string
	rs, err := (&Scanner{}).WithCredentials(t.TempDir(), keys, func(msg string, args ...any) {
		if strings.Contains(msg, "refused") {
			refused = append(refused, args[1].(string))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(rs.(*Scanner).providerConfig)
	var cfg map[string][]string
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg) != 1 || cfg["securitytrails"] == nil {
		t.Fatalf("provider config %v", cfg)
	}
	slices.Sort(refused)
	if strings.Join(refused, ",") != "intelx,redhuntlabs,zoomeyeapi" {
		t.Fatalf("refused %v", refused)
	}
	for _, c := range []struct {
		name, v string
		ok      bool
	}{
		{"intelx", "2.intelx.io:" + k, true},
		{"intelx", "127.0.0.1:" + k, false},
		{"intelx", "[::1]:" + k, false},
		{"intelx", "evilintelx.io:" + k, false},
		{"intelx", "2.intelx.io:8443:" + k, false},
		{"zoomeyeapi", "zoomeye.hk:" + k, true},
		{"zoomeyeapi", "10.0.0.5:" + k, false},
		{"redhuntlabs", "https://reconapi.redhuntlabs.com/community/v1/domains/subdomains:" + k, true},
		{"redhuntlabs", "https://reconapi.redhuntlabs.com:8443/x:" + k, false},
		{"redhuntlabs", "https://user@reconapi.redhuntlabs.com/x:" + k, false},
		{"redhuntlabs", "http://reconapi.redhuntlabs.com/x:" + k, false},
		{"shodan", "anything:goes", true},
		{"shodan", "short", false},
		{"shodan", "has space 12345", false},
		{"facebook", "appid:" + k, false},
		{"censys", "token-only-" + k, false},
	} {
		if got := keyAllowed(c.name, c.v); got != c.ok {
			t.Errorf("%s %q: %v", c.name, c.v, got)
		}
	}
}
