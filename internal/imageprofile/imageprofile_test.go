package imageprofile

import "testing"

// SECURITY: the passive profile admits only T0 compiled-in tools; the
// standard one admits every tier.
func TestAllowsCompiledIn(t *testing.T) {
	old := Name
	t.Cleanup(func() { Name = old })
	for _, tier := range []string{"T0", "T1", "T2", ""} {
		Name = ""
		if !AllowsCompiledIn(tier) {
			t.Errorf("standard profile refused %q", tier)
		}
		Name = "passive"
		if want := tier == "T0"; AllowsCompiledIn(tier) != want {
			t.Errorf("passive profile: %q admitted %v, want %v", tier, AllowsCompiledIn(tier), want)
		}
	}
}
