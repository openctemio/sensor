package naabu

import (
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// scanSettings resolves values as a scan command's config, the way the
// SDK's executor does.
func scanSettings(t *testing.T, values map[string]any) *core.ToolSettings {
	t.Helper()
	ts, err := NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: values})
	if err != nil {
		t.Fatalf("resolve %v: %v", values, err)
	}
	return ts
}

func argsWith(t *testing.T, s *Scanner, values map[string]any) []string {
	t.Helper()
	rs, err := s.WithSettings(scanSettings(t, values))
	if err != nil {
		t.Fatalf("WithSettings(%v): %v", values, err)
	}
	return rs.(*Scanner).buildArgs("example.com", nil)
}

// flagValue returns the value after flag in args, and whether flag is there.
func flagValue(args []string, flag string) (string, bool) {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return "", false
	}
	return args[i+1], true
}

// A pipeline step with ports "80" scans port 80 only. Before, the step's
// config never reached naabu and it scanned the top 100 ports.
func TestWithSettings_PortsLimitTheScan(t *testing.T) {
	got := argsWith(t, NewScanner(), map[string]any{"ports": "80"})
	if v, ok := flagValue(got, "-p"); !ok || v != "80" {
		t.Errorf("-p = %q, %v in %q", v, ok, got)
	}
	if slices.Contains(got, "-top-ports") {
		t.Errorf("default -top-ports still passed with explicit ports: %q", got)
	}
	flagcheck.Check(t, helpFile, got)
}

func TestWithSettings_EveryKeyMapsToItsFlag(t *testing.T) {
	cases := []struct {
		values map[string]any
		flag   string
		want   string
	}{
		{map[string]any{"ports": "80,443,8000-8100"}, "-p", "80,443,8000-8100"},
		{map[string]any{"ports": "top-1000"}, "-top-ports", "1000"},
		{map[string]any{"ports": "full"}, "-p", "-"},
		{map[string]any{"top_ports": 1000}, "-top-ports", "1000"},
		{map[string]any{"exclude_ports": "25,465"}, "-exclude-ports", "25,465"},
		{map[string]any{"retries": 1}, "-retries", "1"},
		{map[string]any{"retries": 0}, "-retries", "0"},
		{map[string]any{"rate": 200}, "-rate", "200"},
	}
	for _, tc := range cases {
		got := argsWith(t, NewScanner(), tc.values)
		if v, ok := flagValue(got, tc.flag); !ok || v != tc.want {
			t.Errorf("%v: %s = %q, %v; args %q", tc.values, tc.flag, v, ok, got)
		}
		// "-" is the value of -p (all ports), not a flag.
		flagcheck.Check(t, helpFile, got, "-")
	}
	// top_ports replaces the default port list instead of adding to it.
	got := argsWith(t, NewScanner(), map[string]any{"top_ports": 1000})
	if n := strings.Count(strings.Join(got, " "), "-top-ports"); n != 1 || slices.Contains(got, "-p") {
		t.Errorf("top_ports 1000: %q", got)
	}
}

// SECURITY: a scan can lower the packet rate, never raise it above the
// sensor's.
func TestWithSettings_RateOnlyLowers(t *testing.T) {
	s := NewScanner() // sensor rate 1000
	if v, _ := flagValue(argsWith(t, s, map[string]any{"rate": 50000}), "-rate"); v != "1000" {
		t.Errorf("rate 50000 on a 1000 pps sensor ran at %s", v)
	}
	s.Rate = 0 // no sensor rate: naabu's default is the ceiling
	if v, _ := flagValue(argsWith(t, s, map[string]any{"rate": 50000}), "-rate"); v != "1000" {
		t.Errorf("rate 50000 with no sensor rate ran at %s", v)
	}
	// The recon wrapper's sensor-level rate is a ceiling too.
	rs, err := NewScanner().WithSettings(scanSettings(t, map[string]any{"rate": 900}))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := flagValue(rs.(*Scanner).buildArgs("example.com", &core.ReconOptions{RateLimit: 300}), "-rate"); v != "300" {
		t.Errorf("rate 900 under a 300 pps sensor option ran at %s", v)
	}
}

// The scanner itself is not modified: concurrent scans keep their own
// settings and later scans get the defaults back.
func TestWithSettings_DoesNotModifyTheScanner(t *testing.T) {
	s := NewScanner()
	_ = argsWith(t, s, map[string]any{"ports": "80", "rate": 10, "retries": 0})
	if got := s.buildArgs("example.com", nil); !slices.Equal(got, NewScanner().buildArgs("example.com", nil)) {
		t.Errorf("scanner changed by a scan's settings: %q", got)
	}
}

// SECURITY: values that are not exactly a port list are refused, by the
// schema (in the SDK's executor) or by the scanner's own checks.
func TestSettings_RefuseInjection(t *testing.T) {
	schema := NewScanner().SettingsSchema()
	for _, v := range []map[string]any{
		{"ports": "-"},
		{"ports": "-p 1-65535"},
		{"ports": "80 -nmap-cli id"},
		{"ports": "80\n-o /tmp/x"},
		{"ports": "80;id"},
		{"ports": ""},
		{"ports": 80},
		{"exclude_ports": "full"},
		{"top_ports": 65535},
		{"rate": 0},
		{"retries": 99},
		{"scan_type": "syn"},
		{"interface": "eth0"},
		{"nmap_cli": "id"},
	} {
		if _, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: v}); err == nil {
			t.Errorf("schema accepted %v", v)
		}
	}
	for _, v := range []map[string]any{
		{"ports": "70000"},
		{"ports": "0"},
		{"ports": "443-80"},
		{"exclude_ports": "99999"},
		{"ports": "80", "top_ports": 100},
	} {
		if _, err := NewScanner().WithSettings(scanSettings(t, v)); err == nil {
			t.Errorf("WithSettings accepted %v", v)
		}
	}
}

// Settings resolved against another schema are refused.
func TestWithSettings_RefusesAnotherSchema(t *testing.T) {
	other := core.MustParseSettingsSchema(`{"$schema":"https://json-schema.org/draft/2020-12/schema","x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{"ports":{"type":"string","x-octm-scope":"scan"}}}`)
	ts, err := other.Resolve(core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"ports": "-p -"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewScanner().WithSettings(ts); err == nil {
		t.Fatal("settings of another schema accepted")
	}
}
