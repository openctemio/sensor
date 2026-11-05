// Package imageprofile is the build-time profile of the sensor binary. The
// passive image is built with
//
//	-X github.com/openctemio/sensor/internal/imageprofile.Name=passive
//
// and a binary of that profile does not contain, as a registered tool, any
// compiled-in tool above T0: it is not registered and not detected, so the
// passive guarantee (no program that can touch a target) holds by
// construction. The image smoke test is the proof.
package imageprofile

// Name is the profile ("" is the standard binary). It is set by the linker
// and never read from the environment or the configuration.
var Name = ""

// Passive reports whether this binary is the passive profile.
func Passive() bool { return Name == "passive" }

// AllowsCompiledIn reports whether a compiled-in tool of this tier (T0, T1,
// ...) is part of this binary: every tool in the standard profile, only T0
// in the passive one.
func AllowsCompiledIn(tier string) bool { return !Passive() || tier == "T0" }
