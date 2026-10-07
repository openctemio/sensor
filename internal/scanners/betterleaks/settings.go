package betterleaks

// What a scan may configure for betterleaks (api RFC-038): whether the git
// history is scanned (betterleaks git) or only the current tree
// (betterleaks dir). The SDK's command executor validates a scan's config
// against the descriptor's schema; withSettings maps it to the command of a
// copy of the scanner.

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is betterleaks's settings schema: the config schema of its
// descriptor (tool.yaml), so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns betterleaks's settings schema
// (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// forScan is the scanner configured with a scan's settings (a copy; the
// scanner itself is not modified, so concurrent scans do not interfere).
func (s *Scanner) forScan(opts *core.ScanOptions) (*Scanner, error) {
	if opts == nil || opts.Settings == nil {
		return s, nil
	}
	return s.withSettings(opts.Settings)
}

// checkDigest refuses settings resolved against another schema (another
// build of this tool, another tool): they are not betterleaks's.
func checkDigest(ts *core.ToolSettings) error {
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return fmt.Errorf("betterleaks settings: resolved against schema %q, not betterleaks's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	return nil
}

// withSettings returns a copy of the scanner configured with a scan's
// settings.
func (s *Scanner) withSettings(ts *core.ToolSettings) (*Scanner, error) {
	if err := checkDigest(ts); err != nil {
		return nil, err
	}
	c := *s
	if h, ok := ts.Bool("history"); ok {
		c.History = h
	}
	return &c, nil
}
