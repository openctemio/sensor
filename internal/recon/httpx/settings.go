package httpx

// What a scan may configure for httpx (api RFC-038): the ports to probe on a
// host target, same-host redirects, technology detection and TLS
// certificate capture. The schema is the config of the tool's descriptor
// (tool.yaml); WithSettings maps each value to a specific flag of a copy of
// the scanner. Nothing from the command becomes free-form text on the
// command line.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is httpx's settings schema: the config schema of its
// descriptor, so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns httpx's settings schema (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// WithSettings returns a copy of the scanner configured with a scan's
// settings; the scanner itself is not modified. Values are checked again
// here and a value it cannot map exactly fails the scan.
func (s *Scanner) WithSettings(ts *core.ToolSettings) (core.ReconScanner, error) {
	if ts == nil {
		return s, nil
	}
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("httpx settings: resolved against schema %q, not httpx's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	if ports, ok := ts.String("ports"); ok {
		if err := checkPortList(ports); err != nil {
			return nil, fmt.Errorf("httpx settings: ports: %w", err)
		}
		c.Ports = ports
	}
	if f, ok := ts.Bool("follow_redirects"); ok {
		// Same host only: a redirect to another host would probe a name
		// nobody asked to scan.
		c.FollowHostRedirects, c.FollowRedirects = f, false
	}
	if t, ok := ts.Bool("tech_detect"); ok {
		c.TechDetect = t
	}
	if t, ok := ts.Bool("tls_grab"); ok {
		c.TLSGrab = t
	}
	return &c, nil
}

// checkPortList checks a list of ports and port ranges: digits, '-' and ','
// only, each port 1-65535, each range in order.
func checkPortList(v string) error {
	if v == "" || len(v) > 2048 {
		return fmt.Errorf("empty or too long")
	}
	for _, part := range strings.Split(v, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := port(lo)
		if err != nil {
			return err
		}
		if isRange {
			b, err := port(hi)
			if err != nil {
				return err
			}
			if b < a {
				return fmt.Errorf("range %s is reversed", part)
			}
		}
	}
	return nil
}

func port(s string) (int, error) {
	if s == "" || len(s) > 5 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("%q is not a port", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q is not from 1 to 65535", s)
	}
	return n, nil
}
