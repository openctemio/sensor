package subfinder

// What a scan may configure for subfinder (api RFC-038): the passive
// sources, recursive enumeration and a cap on the names per root domain.
// The schema is the config of the tool's descriptor (tool.yaml); the SDK's
// command executor validates a scan's config against it and hands the
// values over as typed core.ToolSettings; WithSettings maps each one to a
// specific flag or field of a copy of the scanner. Nothing from the command
// becomes free-form text on the command line.

import (
	"fmt"
	"regexp"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is subfinder's settings schema: the config schema of
// its descriptor, so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// sourceRE is a subfinder source name: lowercase letters and digits only,
// so a value can never be read as a flag or a second list item.
var sourceRE = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

// SettingsSchema returns subfinder's settings schema
// (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// WithSettings returns a copy of the scanner configured with a scan's
// settings; the scanner itself is not modified. Values are checked again
// here (the sensor does not trust the platform) and a value it cannot map
// exactly fails the scan rather than being dropped.
func (s *Scanner) WithSettings(ts *core.ToolSettings) (core.ReconScanner, error) {
	if ts == nil {
		return s, nil
	}
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("subfinder settings: resolved against schema %q, not subfinder's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	if sources, ok := ts.Strings("sources"); ok {
		if len(sources) == 0 || len(sources) > 64 {
			return nil, fmt.Errorf("subfinder settings: sources: 1 to 64 names")
		}
		for _, src := range sources {
			if !sourceRE.MatchString(src) {
				return nil, fmt.Errorf("subfinder settings: sources: %q is not a source name", src)
			}
		}
		c.Sources, c.All = sources, false
	}
	if r, ok := ts.Bool("recursive"); ok {
		c.Recursive = r
	}
	if n, ok := ts.Int("max_results"); ok {
		if n < 1 || n > 5000 {
			return nil, fmt.Errorf("subfinder settings: max_results %d is outside 1-5000", n)
		}
		c.MaxResults = int(n)
	}
	return &c, nil
}

// capPerDomain keeps at most max names per root domain (0: all), in the
// order subfinder reported them.
func capPerDomain(subs []core.Subdomain, max int) []core.Subdomain {
	if max <= 0 {
		return subs
	}
	count := map[string]int{}
	out := subs[:0:0]
	for _, s := range subs {
		if count[s.Domain] >= max {
			continue
		}
		count[s.Domain]++
		out = append(out, s)
	}
	return out
}
