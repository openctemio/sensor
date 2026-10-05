package nuclei

// What a scan may configure for nuclei (api RFC-038): which templates run,
// by tag and severity. The SDK's command executor validates a scan
// command's config against this schema and hands the values over as typed
// core.ToolSettings; withSettings maps each one to a specific flag of a copy
// of the scanner. Nothing from the command becomes free-form text on the
// command line.
//
// Deliberately not settable per scan: template paths or URLs, workflows,
// code/headless/file protocols, interactsh servers, proxies, headers, output
// paths and resolvers (RFC-038 §6.11). Rate limits are the sensor's: a scan
// may only lower them, through the executor's own keys.

import (
	"fmt"
	"slices"

	"github.com/openctemio/sdk-go/pkg/core"
)

// tagPattern is one template tag: lowercase letters, digits, '-' and '_',
// starting with a letter or digit. No comma (nuclei splits tags on it), no
// space, no leading '-': a tag can never become a second tag or a flag.
const tagPattern = `^[a-z0-9][a-z0-9_-]{0,63}$`

// settingsSchemaJSON is nuclei's settings schema.
const settingsSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "title": "nuclei",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "tags": {
      "type": "array", "maxItems": 64, "uniqueItems": true,
      "items": {"type": "string", "pattern": "` + tagPattern + `"},
      "title": "Template tags",
      "description": "Run only templates with one of these tags, e.g. cve, exposure (nuclei -tags). Intrusive tags (default-login, brute force, fuzz, dos, intrusive) are refused.",
      "x-octm-scope": "scan", "x-octm-group": "Templates", "x-octm-order": 10, "x-octm-widget": "tags"
    },
    "exclude_tags": {
      "type": "array", "maxItems": 64, "uniqueItems": true,
      "items": {"type": "string", "pattern": "` + tagPattern + `"},
      "title": "Excluded template tags",
      "description": "Never run templates with these tags (nuclei -etags), in addition to the sensor's own exclusions.",
      "x-octm-scope": "scan", "x-octm-group": "Templates", "x-octm-order": 20, "x-octm-widget": "tags"
    },
    "severity": {
      "type": "array", "minItems": 1, "maxItems": 6, "uniqueItems": true,
      "items": {"enum": ["info", "low", "medium", "high", "critical", "unknown"]},
      "title": "Severities",
      "description": "Run only templates of these severities (nuclei -severity). Default: low to critical.",
      "x-octm-scope": "scan", "x-octm-group": "Templates", "x-octm-order": 30
    }
  }
}`

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns nuclei's settings schema
// (core.SettingsSchemaProvider).
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// withSettings returns a copy of the scanner configured with a scan's
// settings; the scanner itself is not modified, so concurrent scans do not
// interfere. nil settings return the scanner unchanged.
//
// The values were validated against this schema by the SDK's executor; the
// tag rules are checked again here because the sensor does not trust the
// platform, and a value it cannot map exactly fails the scan rather than
// being dropped.
func (s *Scanner) withSettings(ts *core.ToolSettings) (*Scanner, error) {
	if ts == nil {
		return s, nil
	}
	// Settings resolved against another schema are not nuclei's: refuse
	// rather than guess.
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return nil, fmt.Errorf("nuclei settings: resolved against schema %q, not nuclei's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	c := *s
	if tags, ok := ts.Strings("tags"); ok {
		if err := checkTags(tags); err != nil {
			return nil, fmt.Errorf("nuclei settings: tags: %w", err)
		}
		// Templates that log in, brute-force, fuzz or flood are an
		// intrusive-tier decision (RFC-036 O3), never a per-scan setting.
		if err := checkTierTags(tags); err != nil {
			return nil, fmt.Errorf("nuclei settings: %w", err)
		}
		c.Tags = tags
	}
	if ex, ok := ts.Strings("exclude_tags"); ok {
		if err := checkTags(ex); err != nil {
			return nil, fmt.Errorf("nuclei settings: exclude_tags: %w", err)
		}
		// Added to the sensor's exclusions, never replacing them: a scan
		// cannot re-enable what the operator excluded.
		merged := slices.Clone(s.ExcludeTags)
		for _, t := range ex {
			if !slices.Contains(merged, t) {
				merged = append(merged, t)
			}
		}
		c.ExcludeTags = merged
	}
	if sev, ok := ts.Strings("severity"); ok {
		for _, v := range sev {
			switch v {
			case "info", "low", "medium", "high", "critical", "unknown":
			default:
				return nil, fmt.Errorf("nuclei settings: severity %q is not a nuclei severity", v)
			}
		}
		if len(sev) == 0 {
			return nil, fmt.Errorf("nuclei settings: severity is empty")
		}
		c.Severity = sev
	}
	return &c, nil
}

// checkTags checks each tag against tagPattern's rules.
func checkTags(tags []string) error {
	for _, t := range tags {
		if t == "" || len(t) > 64 {
			return fmt.Errorf("%q is not a tag", t)
		}
		for i, r := range t {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (i > 0 && (r == '-' || r == '_'))
			if !ok {
				return fmt.Errorf("%q is not a tag (lowercase letters, digits, '-' and '_')", t)
			}
		}
	}
	return nil
}
