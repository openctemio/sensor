package subfinder

import (
	"slices"
	"testing"

	"github.com/openctemio/contract/secretref"
	"github.com/openctemio/sdk-go/pkg/tool"

	"github.com/openctemio/sensor/internal/toolrun"
)

// The manifest's credential slots are exactly the registry's subfinder
// providers, and the tool reaches only the passive sources' own services:
// network vendor, never any public host, and no keyed provider's host in
// the static list (those are added only when the key is delivered).
func TestManifestSecretsFollowTheRegistry(t *testing.T) {
	m := toolrun.MustManifest(ToolYAML)
	if m.Permissions.Network != tool.NetVendor {
		t.Fatalf("network %q, want vendor", m.Permissions.Network)
	}
	var slots []string
	for _, c := range m.Permissions.Credentials {
		slots = append(slots, c.Name)
	}
	slices.Sort(slots)
	if want := secretref.ProvidersForTool("subfinder"); !slices.Equal(slots, want) {
		t.Fatalf("slots %v\nregistry %v", slots, want)
	}
	keyed := map[string]bool{}
	for _, id := range secretref.ProvidersForTool("subfinder") {
		p, _ := secretref.LookupProvider(id)
		for _, h := range p.Hosts {
			keyed[h] = true
		}
	}
	// A source with an optional key is also queried without one: its host
	// may be listed.
	optional := map[string]bool{"api.hackertarget.com": true, "www.reconeer.com": true}
	for _, h := range m.Permissions.VendorHosts {
		if keyed[h] && !optional[h] {
			t.Errorf("vendor host %s belongs to a keyed source only", h)
		}
	}
}
