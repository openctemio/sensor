package imageprofile

import "testing"

// SECURITY: the passive profile admits only T0 compiled-in tools, the relay
// profile none at all; the standard one admits every tier.
func TestAllowsCompiledIn(t *testing.T) {
	old := Name
	t.Cleanup(func() { Name = old })
	for _, tier := range []string{"T0", "T1", "T2", ""} {
		Name = ""
		if !AllowsCompiledIn(tier) {
			t.Errorf("standard profile refused %q", tier)
		}
		Name = NamePassive
		if want := tier == "T0"; AllowsCompiledIn(tier) != want {
			t.Errorf("passive profile: %q admitted %v, want %v", tier, AllowsCompiledIn(tier), want)
		}
		Name = NameRelay
		if AllowsCompiledIn(tier) {
			t.Errorf("relay profile admitted a %q tool", tier)
		}
	}
}

// SECURITY: only the relay profile registers no tool.
func TestAllowsTools(t *testing.T) {
	old := Name
	t.Cleanup(func() { Name = old })
	for name, want := range map[string]bool{"": true, NamePassive: true, NameRelay: false} {
		Name = name
		if AllowsTools() != want {
			t.Errorf("profile %q: AllowsTools %v, want %v", name, !want, want)
		}
	}
	Name = NameRelay
	if !Relay() || Passive() {
		t.Fatal("the relay profile is not recognized as relay only")
	}
}
