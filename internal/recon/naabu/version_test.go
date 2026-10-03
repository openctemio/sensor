package naabu

import "testing"

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"[INF] Current Version: v1.6.10\n": "v1.6.10",
		"naabu v1.3.0\n":                   "v1.3.0",
	} {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
