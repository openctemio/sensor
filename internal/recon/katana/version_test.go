package katana

import "testing"

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"[INF] Current Version: v1.6.10\n": "v1.6.10",
		"katana v1.3.0\n":                  "v1.3.0",
		// katana 1.7.0 prints a banner, then "Current version:".
		"  __ \n\t\tprojectdiscovery.io\n\n[INF] Current version: v1.7.0\n": "v1.7.0",
		// katana 1.7.0 prints its banner, then "Current version:".
		"   __        __\n\t\tprojectdiscovery.io\n\n[INF] Current version: v1.7.0\n": "v1.7.0",
	} {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
