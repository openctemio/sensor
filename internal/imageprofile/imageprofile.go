// Package imageprofile is the build-time profile of the sensor binary. The
// passive and relay images are built with
//
//	-X github.com/openctemio/sensor/internal/imageprofile.Name=passive
//	-X github.com/openctemio/sensor/internal/imageprofile.Name=relay
//
// A binary of the passive profile does not contain, as a registered tool, any
// compiled-in tool above T0: it is not registered and not detected, so the
// passive guarantee (no program that can touch a target) holds by
// construction. A binary of the relay profile registers no tool at all: it
// only relays the platform's signed feeds (docs/PROFILES.md). The image smoke
// test is the proof for both.
package imageprofile

// The profile names a binary can be built with.
const (
	NamePassive = "passive"
	NameRelay   = "relay"
)

// Name is the profile ("" is the standard binary). It is set by the linker
// and never read from the environment or the configuration.
var Name = ""

// Passive reports whether this binary is the passive profile.
func Passive() bool { return Name == NamePassive }

// Relay reports whether this binary is the relay profile: the feed relay and
// nothing else, no tool of any tier.
func Relay() bool { return Name == NameRelay }

// AllowsTools reports whether this binary registers tools at all (every
// profile but relay).
func AllowsTools() bool { return !Relay() }

// AllowsCompiledIn reports whether a compiled-in tool of this tier (T0, T1,
// ...) is part of this binary: every tool in the standard profile, only T0
// in the passive one, none in the relay one.
func AllowsCompiledIn(tier string) bool {
	switch Name {
	case NameRelay:
		return false
	case NamePassive:
		return tier == "T0"
	}
	return true
}
