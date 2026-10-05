package main

// `openctemio-sensor pair [CODE]`: interactive pairing (api
// docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.7). The sensor
// makes its own Ed25519 key in <state dir>/identity (0600 files in a 0700
// directory), asks the platform to pair, prints a code and a fingerprint,
// and waits until an administrator who compared the fingerprint approves
// it. No secret is ever typed or pasted; afterwards the daemon runs with
// no API_KEY and signs every request with that key.
//
//	pair                 print a code to enter under Sensors > Pair a sensor
//	pair K7QM-4ZTD       attach to a code an administrator created with
//	                     "Expect a sensor" and print the fingerprint to compare
//	pair -repair         replace a lost or compromised key of this sensor
//	                     (a new key; the administrator approves it again)

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

// pairDeps are what the command reaches outside the process (tests replace
// them).
type pairDeps struct {
	pair   func(context.Context, identity.PairOptions) (*identity.Identity, error)
	getenv func(string) string
}

// binName is the command name people type.
const binName = "openctemio-sensor"

var defaultPairDeps = pairDeps{pair: identity.Pair, getenv: os.Getenv}

// runPairCommand runs `pair …` and returns the exit code: 0 paired,
// 1 refused or failed, 2 usage.
func runPairCommand(args []string, stdout, stderr io.Writer, d pairDeps) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiURL := fs.String("api-url", "", "Platform API URL (or API_URL env)")
	stateDir := fs.String("state-dir", "", "State directory; the identity is kept in <dir>/identity (or SENSOR_STATE_DIR env; default "+sensorkit.ResolveStateDir("")+")")
	name := fs.String("name", "", "Name to propose for the sensor (or SENSOR_NAME env); the administrator may change it")
	repair := fs.Bool("repair", false, "Re-pair this sensor with a new key (lost or compromised key); needs an administrator's approval")
	caFingerprint := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the platform CA from the install snippet (or "+sensorkit.EnvCAFingerprint+" env)")
	platformKey := fs.String("platform-key", "", "Thumbprint of the platform pairing key from the install snippet (or "+sensorkit.EnvPlatformKey+" env)")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: %s pair [flags] [CODE]\n\n"+
			"Pairs this sensor with the platform. Without CODE it prints a code for an administrator to enter\n"+
			"under Sensors > Pair a sensor; with the CODE an administrator created (Expect a sensor) it attaches\n"+
			"to it. Either way, approve only when the fingerprint shown here matches the console.\n\nFlags:\n", binName)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	code := fs.Arg(0)
	url := firstNonEmpty(*apiURL, d.getenv("API_URL"))
	if url == "" {
		_, _ = fmt.Fprintln(stderr, "Error: set the platform API URL (-api-url or API_URL)")
		return 2
	}
	if fp := firstNonEmpty(*caFingerprint, d.getenv(sensorkit.EnvCAFingerprint)); fp != "" {
		pin, err := httpsec.ParseCAFingerprint(fp)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %s: %v\n", sensorkit.EnvCAFingerprint, err)
			return 2
		}
		if sensorkit.PinnedURLHasIPHost(url) {
			_, _ = fmt.Fprintf(stderr, "Error: %s is set but the platform URL %s is an IP address; a pinned CA needs the host name in the platform certificate\n",
				sensorkit.EnvCAFingerprint, url)
			return 2
		}
		httpsec.SetAPIPinnedCA(pin)
	} else if f := d.getenv(sensorkit.EnvCACertFile); f != "" {
		pool, err := httpsec.LoadCAFile(f)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %s: %v\n", sensorkit.EnvCACertFile, err)
			return 2
		}
		httpsec.SetAPIRootCAs(pool)
	}

	store := identity.NewStore(sensorkit.ResolveStateDir(firstNonEmpty(*stateDir, d.getenv(sensorkit.EnvStateDir))))
	o := identity.PairOptions{
		BaseURL:        url,
		Store:          store,
		Code:           code,
		Host:           identity.DefaultHostFacts(binName, Version, firstNonEmpty(*name, d.getenv(sensorkit.EnvSensorName))),
		PlatformKeyPin: firstNonEmpty(*platformKey, d.getenv(sensorkit.EnvPlatformKey)),
		Out:            stdout,
		UserAgent:      binName + "/" + Version,
	}
	current, _, err := store.Load()
	switch {
	case err == nil && !*repair:
		_, _ = fmt.Fprintf(stderr, "This sensor is already paired as %q (%s, key SHA256:%s; identity in %s).\n"+
			"Run `%s pair -repair` to replace its key.\n", current.Name, current.SensorID, current.KeyID, store.Dir(), binName)
		return 1
	case err == nil:
		o.RepairSensorID, o.NewKey = current.SensorID, true
	case errors.Is(err, identity.ErrNoIdentity):
		if *repair {
			_, _ = fmt.Fprintln(stderr, "Error: -repair needs this sensor's identity; it has none (pair without -repair)")
			return 2
		}
	default:
		// Loose permissions, another owner, a key mismatch: the fix is in
		// the message.
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	id, err := d.pair(ctx, o)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Start the sensor without API_KEY; it signs its requests with this key (sensor %s).\n", id.SensorID)
	return 0
}
