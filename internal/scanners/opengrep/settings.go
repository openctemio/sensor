package opengrep

// What a scan may configure for opengrep (api RFC-038): cross-function
// taint, the per-rule timeout and the largest file a scan reads; the
// sensor's settings also decide the cores and memory one scan takes. The
// SDK's command executor validates a scan's config against the
// descriptor's schema; withSettings maps it to a copy of the scanner.

import (
	"fmt"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// settingsSchemaJSON is opengrep's settings schema: the config schema of
// its descriptor (tool.yaml), so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns opengrep's settings schema
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

// withSettings returns a copy of the scanner configured with a scan's
// settings. Settings resolved against another schema (another build of
// this tool, another tool) are refused.
func (s *Scanner) withSettings(ts *core.ToolSettings) (*Scanner, error) {
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("opengrep settings: resolved against schema %q, not opengrep's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	if v, ok := ts.Bool("taint_intrafile"); ok {
		c.TaintIntrafile = v
	}
	if v, ok := ts.Int("rule_timeout"); ok {
		c.RuleTimeout = int(v)
	}
	if v, ok := ts.Int("max_target_bytes"); ok {
		c.MaxTargetBytes = int64(v)
	}
	if v, ok := ts.Int("jobs"); ok {
		c.Jobs = int(v)
	}
	if v, ok := ts.Int("max_memory_mb"); ok {
		c.MaxMemory = int(v)
	}
	return &c, nil
}
