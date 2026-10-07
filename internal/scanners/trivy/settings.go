package trivy

// What a scan may configure for trivy (api RFC-038): development
// dependencies, operating-system packages and the IaC frameworks checked.
// The SDK's command executor validates a scan's config against the
// descriptor's schema; withSettings maps each value to a specific flag of a
// copy of the scanner, from closed sets.

import (
	"fmt"
	"slices"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// misconfigScanners are the IaC frameworks a scan may select
// (trivy --misconfig-scanners).
var misconfigScanners = []string{"azure-arm", "cloudformation", "dockerfile", "helm", "kubernetes",
	"terraform", "terraformplan-json", "terraformplan-snapshot"}

// settingsSchemaJSON is trivy's settings schema: the config schema of its
// descriptor (tool.yaml), so the two cannot drift.
var settingsSchemaJSON = string(toolrun.MustManifest(ToolYAML).Config)

var settingsSchema = core.MustParseSettingsSchema(settingsSchemaJSON)

// SettingsSchema returns trivy's settings schema
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
// build of this tool, another tool): they are not trivy's.
func checkDigest(ts *core.ToolSettings) error {
	if ts.SchemaDigest() != settingsSchema.Digest() {
		return fmt.Errorf("trivy settings: resolved against schema %q, not trivy's %q", ts.SchemaDigest(), settingsSchema.Digest())
	}
	return nil
}

// withSettings returns a copy of the scanner configured with a scan's
// settings. Values are checked again here and a value it cannot map
// exactly fails the scan.
func (s *Scanner) withSettings(ts *core.ToolSettings) (*Scanner, error) {
	if err := checkDigest(ts); err != nil {
		return nil, err
	}
	c := *s
	if d, ok := ts.Bool("dev_deps"); ok {
		c.IncludeDevDeps = d
	}
	if osPkgs, ok := ts.Bool("os_pkgs"); ok {
		if osPkgs {
			c.PkgTypes = []string{"os", "library"}
		} else {
			c.PkgTypes = []string{"library"}
		}
	}
	if fw, ok := ts.Strings("frameworks"); ok {
		if len(fw) == 0 {
			return nil, fmt.Errorf("trivy settings: frameworks is empty")
		}
		for _, f := range fw {
			if !slices.Contains(misconfigScanners, f) {
				return nil, fmt.Errorf("trivy settings: frameworks: %q is not a trivy misconfiguration scanner", f)
			}
		}
		c.MisconfigScanners = slices.Clone(fw)
	}
	return &c, nil
}
