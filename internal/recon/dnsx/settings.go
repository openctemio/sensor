package dnsx

// What a scan may configure for dnsx (api RFC-038): the record types to
// query and wildcard filtering. The schema is the config of the tool's
// descriptor (tool.yaml); WithSettings maps each value to a specific flag
// of a copy of the scanner. Nothing from the command becomes free-form text
// on the command line.

import (
	"fmt"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is dnsx's settings schema: the config schema of its
// descriptor, so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// recordFlags are the record types a scan may ask for, each one dnsx flag.
var recordFlags = map[string]bool{"a": true, "aaaa": true, "cname": true, "mx": true, "ns": true, "txt": true}

// SettingsSchema returns dnsx's settings schema (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// WithSettings returns a copy of the scanner configured with a scan's
// settings; the scanner itself is not modified. Values are checked again
// here and a value it cannot map exactly fails the scan.
func (s *Scanner) WithSettings(ts *core.ToolSettings) (core.ReconScanner, error) {
	if ts == nil {
		return s, nil
	}
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("dnsx settings: resolved against schema %q, not dnsx's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	if types, ok := ts.Strings("record_types"); ok {
		if len(types) == 0 {
			return nil, fmt.Errorf("dnsx settings: record_types is empty")
		}
		out := make([]string, 0, len(types))
		for _, t := range types {
			if !recordFlags[t] {
				return nil, fmt.Errorf("dnsx settings: record_types: %q is not a record type a scan may query", t)
			}
			out = append(out, strings.ToUpper(t))
		}
		c.RecordTypes, c.QueryAll = out, false
	}
	if w, ok := ts.Bool("wildcard_filter"); ok {
		c.RespectWildcard = w
	}
	return &c, nil
}
