package codeql

// What a scan may configure for codeql (api RFC-038): the language its
// database is built for. The SDK's command executor validates a scan's
// config against the descriptor's schema; withSettings maps the value to
// the --language flag of a copy of the scanner, from a closed set.

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is codeql's settings schema: the config schema of its
// descriptor (tool.yaml), so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns codeql's settings schema
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
// build of this tool, another tool): they are not codeql's.
func checkDigest(ts *core.ToolSettings) error {
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return fmt.Errorf("codeql settings: resolved against schema %q, not codeql's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	return nil
}

// withSettings returns a copy of the scanner configured with a scan's
// settings. Values are checked again here (the sensor does not trust the
// platform) and a value it cannot map exactly fails the scan.
func (s *Scanner) withSettings(ts *core.ToolSettings) (*Scanner, error) {
	if err := checkDigest(ts); err != nil {
		return nil, err
	}
	c := *s
	if langs, ok := ts.Strings("languages"); ok {
		// CodeQL builds one database per language: exactly one.
		if len(langs) != 1 {
			return nil, fmt.Errorf("codeql settings: languages: exactly one language, got %d", len(langs))
		}
		l := Language(langs[0])
		if !l.IsValid() {
			return nil, fmt.Errorf("codeql settings: languages: %q is not a CodeQL language", langs[0])
		}
		c.Language = l
	}
	return &c, nil
}
