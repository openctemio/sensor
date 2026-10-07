package katana

// What a scan may configure for katana (api RFC-038): the crawl depth,
// JavaScript parsing and a cap on the URLs per start URL. The schema is the
// config of the tool's descriptor (tool.yaml); WithSettings maps each value
// to a specific flag or field of a copy of the scanner. Nothing from the
// command becomes free-form text on the command line.

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is katana's settings schema: the config schema of its
// descriptor, so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns katana's settings schema
// (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// WithSettings returns a copy of the scanner configured with a scan's
// settings; the scanner itself is not modified. Values are checked again
// here and a value it cannot map exactly fails the scan.
func (s *Scanner) WithSettings(ts *core.ToolSettings) (core.ReconScanner, error) {
	if ts == nil {
		return s, nil
	}
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("katana settings: resolved against schema %q, not katana's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	if d, ok := ts.Int("depth"); ok {
		if d < 1 || d > 10 {
			return nil, fmt.Errorf("katana settings: depth %d is outside 1-10", d)
		}
		c.Depth = int(d)
	}
	if js, ok := ts.Bool("js_parse"); ok {
		c.JSCrawl = js
	}
	if n, ok := ts.Int("max_urls"); ok {
		if n < 1 || n > 5000 {
			return nil, fmt.Errorf("katana settings: max_urls %d is outside 1-5000", n)
		}
		c.MaxURLs = int(n)
	}
	return &c, nil
}
