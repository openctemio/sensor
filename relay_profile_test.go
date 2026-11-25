package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/feedrelay"
	"github.com/openctemio/sdk-go/pkg/sensorkit"

	"github.com/openctemio/sensor/internal/imageprofile"
	"github.com/openctemio/sensor/internal/toolrun"
)

// fakeRelayKit stands in for the SDK kit of a shared sensor: its registry
// starts with what sensorkit.New adds for a shared sensor, and
// ServeFeedRelay adds feed.relay@1 as the SDK does when it can relay.
type fakeRelayKit struct {
	reg      *core.ToolRegistry
	canRelay bool
	served   bool
	envSeen  string
}

func newFakeRelayKit(canRelay bool) *fakeRelayKit {
	reg := core.NewToolRegistry()
	reg.AddCapabilities(sensorkit.CapabilitySharedIsolation)
	return &fakeRelayKit{reg: reg, canRelay: canRelay}
}

func (f *fakeRelayKit) Tools() *core.ToolRegistry { return f.reg }

func (f *fakeRelayKit) ServeFeedRelay() (bool, error) {
	f.served = true
	f.envSeen = os.Getenv(sensorkit.EnvFeedRelay)
	if !f.canRelay {
		return false, &sensorkit.Error{Code: sensorkit.ExitUsage, Err: errors.New("SENSOR_FEED_RELAY=1: cannot relay")}
	}
	f.reg.AddCapabilities(feedrelay.Capability)
	return true, nil
}

// SECURITY (placement): the platform places work on a sensor only by the
// capabilities it reports (a job's required_capabilities, the tool names,
// and shared.isolation@1 for every shared job). A relay-profile sensor
// reports feed.relay@1 and nothing else: no tool, no scan capability, and
// not the shared isolation profile, so no scan job is ever offered to it.
func TestRelayProfileReportsNoScanCapabilities(t *testing.T) {
	old := imageprofile.Name
	t.Cleanup(func() { imageprofile.Name = old })
	imageprofile.Name = imageprofile.NameRelay
	t.Setenv(sensorkit.EnvFeedRelay, "")
	t.Setenv(sensorkit.EnvCTLookup, "")

	k := newFakeRelayKit(true)
	// What the relay daemon would detect and add: nothing.
	for _, nt := range forProfile(nativeTools) {
		t.Fatalf("the relay profile would add the tool %s", nt.name)
	}
	if err := serveRelayOnly(k); err != nil {
		t.Fatalf("serveRelayOnly: %v", err)
	}
	if k.envSeen != "1" {
		t.Errorf("the feed relay was not required (SENSOR_FEED_RELAY=%q)", k.envSeen)
	}
	rep := k.reg.CapabilityReport(context.Background())
	if len(rep.Tools) != 0 {
		t.Errorf("a relay sensor reports tools: %+v", rep.Tools)
	}
	if !slices.Equal(rep.Capabilities, []string{feedrelay.Capability}) {
		t.Fatalf("a relay sensor reports %v, want only %s", rep.Capabilities, feedrelay.Capability)
	}
	if !slices.Equal(relayCommandTypes, []string{"health_check"}) {
		t.Errorf("a relay sensor accepts %v; it must refuse scans", relayCommandTypes)
	}
}

// SECURITY: the relay binary registers no tool at all (`tools manifests` is
// empty and the tool child runs nothing). The tools register at package
// init, so this holds only in a binary linked with the relay profile; here
// the check is that registration in the relay profile is refused for every
// tool the standard binary carries.
func TestRelayProfileRegistersNothing(t *testing.T) {
	old := imageprofile.Name
	t.Cleanup(func() { imageprofile.Name = old })
	if len(toolrun.Registered()) == 0 {
		t.Fatal("the standard test binary registered no tool: the check would prove nothing")
	}
	imageprofile.Name = imageprofile.NameRelay
	for _, tl := range toolrun.Registered() {
		if imageprofile.AllowsCompiledIn(string(tl.Manifest().Tier)) || imageprofile.AllowsTools() {
			t.Fatalf("the relay profile would register %s", tl.Manifest().Name)
		}
	}
}

// The relay image fails loudly instead of idling: the relay turned off, a
// CT lookup required, or a sensor that cannot relay (an organization's
// sensor, no pinned job-signing key) stop it with a usage error.
func TestRelayProfileRefusals(t *testing.T) {
	cases := []struct {
		name, relay, ct string
		canRelay        bool
		want            error
		served          bool
	}{
		{name: "relay off", relay: "0", want: errRelayOff},
		{name: "CT lookup required", ct: "1", want: errRelayCT},
		{name: "cannot relay", canRelay: false, served: true},
		{name: "auto", relay: "auto", canRelay: true, served: true},
		{name: "required", relay: "1", canRelay: true, served: true},
		{name: "CT off", ct: "0", canRelay: true, served: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(sensorkit.EnvFeedRelay, c.relay)
			t.Setenv(sensorkit.EnvCTLookup, c.ct)
			k := newFakeRelayKit(c.canRelay)
			err := serveRelayOnly(k)
			switch {
			case c.want != nil:
				if !errors.Is(err, c.want) {
					t.Fatalf("err %v, want %v", err, c.want)
				}
			case !c.canRelay:
				if err == nil || sensorkit.ExitCode(err) != sensorkit.ExitUsage {
					t.Fatalf("a sensor that cannot relay started: %v", err)
				}
			case err != nil:
				t.Fatalf("serveRelayOnly: %v", err)
			}
			if k.served != c.served {
				t.Errorf("ServeFeedRelay called %v, want %v", k.served, c.served)
			}
			if c.want != nil && sensorkit.ExitCode(err) != sensorkit.ExitUsage {
				t.Errorf("exit code %d, want %d", sensorkit.ExitCode(err), sensorkit.ExitUsage)
			}
		})
	}
}
