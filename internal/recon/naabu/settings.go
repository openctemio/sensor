package naabu

// What a scan may configure for naabu (api RFC-038): the ports to scan, the
// retries, and a lower packet rate. The SDK's command executor validates a
// scan command's config against this schema and hands the values over as
// typed core.ToolSettings; WithSettings maps each one to a specific flag of
// a copy of the scanner. Nothing from the command becomes free-form text on
// the command line.
//
// Deliberately not settable per scan: the scan type (a SYN scan needs raw
// sockets; the sensor pins connect), interface, source IP, resolvers,
// output paths, host discovery and nmap (naabu -nmap-cli runs a command).

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// portListPattern is a comma-separated list of ports and port ranges, the
// only syntax WithSettings passes to -p / -exclude-ports. No sign, space,
// letter or second line can appear, so a value can never be read as a flag.
const portListPattern = `^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$`

// settingsSchemaJSON is naabu's settings schema.
const settingsSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "title": "naabu",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ports": {
      "type": "string", "minLength": 1, "maxLength": 2048,
      "pattern": "^(?:top-100|top-1000|full|[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*)$",
      "title": "Ports",
      "description": "Ports to scan: a list such as 80,443,8000-8100, or top-100, top-1000 or full (naabu -p / -top-ports). Default: the top 100 ports.",
      "x-octm-scope": "scan", "x-octm-group": "Ports", "x-octm-order": 10
    },
    "top_ports": {
      "type": "integer", "enum": [100, 1000],
      "title": "Top ports",
      "description": "Scan the N most common ports instead of a list (naabu -top-ports). Not together with ports.",
      "x-octm-scope": "scan", "x-octm-group": "Ports", "x-octm-order": 20
    },
    "exclude_ports": {
      "type": "string", "minLength": 1, "maxLength": 2048,
      "pattern": "` + portListPattern + `",
      "title": "Excluded ports",
      "description": "Ports never scanned, e.g. 25,465 (naabu -exclude-ports).",
      "x-octm-scope": "scan", "x-octm-group": "Ports", "x-octm-order": 30
    },
    "rate": {
      "type": "integer", "minimum": 1, "maximum": 100000,
      "title": "Packets per second",
      "description": "Run slower than the sensor's own rate (naabu -rate). A scan can only lower it: a value above the sensor's rate runs at the sensor's rate.",
      "x-octm-scope": "scan", "x-octm-group": "Performance", "x-octm-order": 40
    },
    "retries": {
      "type": "integer", "minimum": 0, "maximum": 10,
      "title": "Retries",
      "description": "Probes per port before it counts as closed (naabu -retries).",
      "x-octm-scope": "scan", "x-octm-group": "Performance", "x-octm-order": 50
    }
  }
}`

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns naabu's settings schema (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// WithSettings returns a copy of the scanner configured with a scan's
// settings; the scanner itself is not modified, so concurrent scans do not
// interfere. nil settings return the scanner unchanged.
//
// The values were validated against this schema by the SDK's executor;
// port lists are checked again here (port numbers 1-65535, ranges in order)
// because the sensor does not trust the platform, and a value it cannot map
// exactly fails the scan rather than being dropped.
func (s *Scanner) WithSettings(ts *core.ToolSettings) (core.ReconScanner, error) {
	if ts == nil {
		return s, nil
	}
	// Settings resolved against another schema (another build of this
	// tool, another tool) are not naabu's: refuse rather than guess.
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("naabu settings: resolved against schema %q, not naabu's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	ports, hasPorts := ts.String("ports")
	top, hasTop := ts.Int("top_ports")
	if hasPorts && hasTop {
		return nil, fmt.Errorf("naabu settings: set ports or top_ports, not both")
	}
	if hasPorts {
		if err := checkPortList(ports, true); err != nil {
			return nil, fmt.Errorf("naabu settings: ports: %w", err)
		}
		c.Ports, c.TopPorts, c.PortList = ports, 0, nil
	}
	if hasTop {
		c.Ports, c.TopPorts, c.PortList = "", int(top), nil
	}
	if ex, ok := ts.String("exclude_ports"); ok {
		if err := checkPortList(ex, false); err != nil {
			return nil, fmt.Errorf("naabu settings: exclude_ports: %w", err)
		}
		c.ExcludePorts = ex
	}
	if r, ok := ts.Int("rate"); ok {
		c.scanRate = int(r)
	}
	if n, ok := ts.Int("retries"); ok {
		c.Retries = int(n)
		c.retriesSet = true
	}
	return &c, nil
}

// checkPortList checks a port list: each port 1-65535, each range low-high
// in order; keywords (top-100, top-1000, full) only when allowed.
func checkPortList(v string, keywords bool) error {
	switch v {
	case "top-100", "top-1000", "full":
		if keywords {
			return nil
		}
		return fmt.Errorf("%q is not a port list", v)
	}
	if v == "" {
		return fmt.Errorf("empty")
	}
	for _, part := range strings.Split(v, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := portNumber(lo)
		if err != nil {
			return err
		}
		if !isRange {
			continue
		}
		b, err := portNumber(hi)
		if err != nil {
			return err
		}
		if b < a {
			return fmt.Errorf("range %s is reversed", part)
		}
	}
	return nil
}

func portNumber(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, fmt.Errorf("%q is not a port", s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q is not a port", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q is not from 1 to 65535", s)
	}
	return n, nil
}

// SettingsSchemaJSON returns naabu's settings schema as JSON (the tool
// manifest's configuration schema).
func SettingsSchemaJSON() string { return settingsSchemaJSON }
