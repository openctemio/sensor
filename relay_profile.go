package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"

	"github.com/openctemio/sensor/internal/imageprofile"
)

// The relay profile (docs/PROFILES.md, internal/imageprofile): a sensor that
// only relays the platform's signed feeds (api RFC-142). Its binary registers
// no tool, and its daemon serves the feed relay and nothing else: no scan,
// lookup, validation, retest or content command, and no capability the
// platform places work by except feed.relay@1.

// relayCommandTypes are the only command types a relay sensor accepts: the
// health check. Every other command (a scan above all) is refused by the
// sensor even if the platform offered one.
var relayCommandTypes = []string{"health_check"}

// relayKit is what serveRelayOnly needs of the sensor kit.
type relayKit interface {
	ServeFeedRelay() (bool, error)
	Tools() *core.ToolRegistry
}

// errRelayOff: the relay image with the feed relay turned off does nothing.
var errRelayOff = &sensorkit.Error{Code: sensorkit.ExitUsage, Err: errors.New("the relay image only relays the platform's feeds, and " +
	sensorkit.EnvFeedRelay + "=0 turns that off; unset it, or run another sensor image")}

// errRelayCT: CT lookups are not part of the relay profile.
var errRelayCT = &sensorkit.Error{Code: sensorkit.ExitUsage, Err: errors.New("the relay image serves no CT lookups (" +
	sensorkit.EnvCTLookup + "=1); run the standard image on a shared sensor for them, or unset it")}

// serveRelayOnly turns the feed relay on (required: a relay sensor that
// cannot relay fails at start, naming the reason) and withdraws every
// capability that would let the platform place a job here. The shared
// isolation capability is withdrawn too: the platform hands shared jobs only
// to sensors reporting it, so a relay sensor is never offered one.
func serveRelayOnly(kit relayKit) error {
	switch strings.TrimSpace(os.Getenv(sensorkit.EnvFeedRelay)) {
	case "0":
		return errRelayOff
	case "", "auto":
		// Required, so a sensor that cannot relay says why and exits.
		if err := os.Setenv(sensorkit.EnvFeedRelay, "1"); err != nil {
			return err
		}
	}
	if strings.TrimSpace(os.Getenv(sensorkit.EnvCTLookup)) == "1" {
		return errRelayCT
	}
	on, err := kit.ServeFeedRelay()
	if err != nil {
		return err
	}
	if !on {
		return &sensorkit.Error{Code: sensorkit.ExitUsage, Err: errors.New("the feed relay did not start; the relay image does nothing else")}
	}
	kit.Tools().RemoveCapabilities(sensorkit.CapabilitySharedIsolation)
	return nil
}

// relayProfile reports whether this binary is the relay profile.
func relayProfile() bool { return imageprofile.Relay() }

// runRelay runs the daemon of the relay profile: the feed relay, heartbeats
// and the local policy's SIGHUP reload, nothing else. It does not return.
func runRelay(ctx context.Context, kit *sensorkit.Kit, opts daemonOptions) {
	if opts.jobID != "" {
		sensorkit.Exit(&sensorkit.Error{Code: sensorkit.ExitUsage, Err: errors.New("the relay image runs no job")})
	}
	sensorkit.Exit(serveRelayOnly(kit))
	stopReload := kit.ReloadLocalPolicyOnSIGHUP(ctx, core.LocalPolicyOptions{Path: opts.localPolicy}, nil)
	defer stopReload()
	sensorkit.Exit(kit.Run(ctx))
}
