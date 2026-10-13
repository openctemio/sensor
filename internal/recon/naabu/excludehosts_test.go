package naabu

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/sensor/internal/recon/internal/flagcheck"
)

// The job's exclusions reach naabu as -exclude-hosts, ranges written as
// prefixes, and travel to the tool child.
func TestWithExcludeHosts(t *testing.T) {
	rs, err := NewScanner().WithExcludeHosts([]string{" 198.51.100.7 ", "198.51.100.64/27", "198.51.100.10-198.51.100.12", "::ffff:203.0.113.1"})
	if err != nil {
		t.Fatal(err)
	}
	s := rs.(*Scanner)
	got := s.buildArgs("198.51.100.0/24", nil)
	i := slices.Index(got, "-exclude-hosts")
	if i < 0 || got[i+1] != "198.51.100.7,198.51.100.64/27,198.51.100.10/31,198.51.100.12/32,203.0.113.1" {
		t.Fatalf("args = %q", got)
	}
	flagcheck.Check(t, helpFile, got)

	raw, _ := json.Marshal(s)
	var back Scanner
	if err := json.Unmarshal(raw, &back); err != nil || !slices.Equal(back.ExcludeHosts, s.ExcludeHosts) {
		t.Fatalf("decoded exclude hosts = %v (err %v)", back.ExcludeHosts, err)
	}

	if same, _ := NewScanner().WithExcludeHosts(nil); slices.Contains(same.(*Scanner).buildArgs("198.51.100.0/24", nil), "-exclude-hosts") {
		t.Fatal("no exclusions still passed -exclude-hosts")
	}
}

// An exclusion naabu cannot read refuses the job instead of being dropped;
// nothing that looks like a flag reaches the command line.
func TestWithExcludeHosts_Refuses(t *testing.T) {
	for _, bad := range []string{"example.com", "-p 1-65535", "198.51.100.9-198.51.100.1", "10.0.0.1-2001:db8::1", ""} {
		if _, err := NewScanner().WithExcludeHosts([]string{bad}); err == nil {
			t.Errorf("exclusion %q was taken", bad)
		}
	}
	many := make([]string, maxExcludeHosts+1)
	for i := range many {
		many[i] = "198.51.100.1"
	}
	if _, err := NewScanner().WithExcludeHosts(many); err == nil {
		t.Error("an over-long exclusion list was taken")
	}
}
