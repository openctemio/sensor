package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// customForbiddenKeys are the top-level template keys a custom template may
// not have: protocols that run code on the sensor (code, javascript), read
// its disk (file) or drive a browser (headless). Compared case-insensitively
// because nuclei also reads JSON templates, whose keys match any case.
var customForbiddenKeys = []string{"code", "javascript", "file", "headless"}

// maxCustomTemplateBytes bounds one custom template file read for the check
// (the SDK already refuses templates over 1 MiB).
const maxCustomTemplateBytes = 2 << 20

// CheckCustomTemplates refuses a custom-template directory with a template
// that uses a protocol the sensor never runs for custom templates (see
// customForbiddenKeys) or asks to be self-contained. The platform refuses
// the same at upload and signs only what it accepted; this is the sensor's
// own check, so a template that slipped past the platform (or a platform
// signing key in the wrong hands) still cannot run code here. Every regular
// file in dir is checked; a file that is not YAML is refused as well, since
// nuclei could not load it as a template either.
func CheckCustomTemplates(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("custom templates: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return fmt.Errorf("custom template %q is not a regular file", e.Name())
		}
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			return fmt.Errorf("custom template %q: %w", e.Name(), err)
		}
		if info.Size() > maxCustomTemplateBytes {
			return fmt.Errorf("custom template %q is too large", e.Name())
		}
		raw, err := os.ReadFile(path) //nolint:gosec // path is a file the executor wrote into its own temp dir
		if err != nil {
			return fmt.Errorf("custom template %q: %w", e.Name(), err)
		}
		if err := checkCustomTemplate(raw); err != nil {
			return fmt.Errorf("custom template %q refused: %w", e.Name(), err)
		}
	}
	return nil
}

func checkCustomTemplate(raw []byte) error {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("not a YAML template: %w", err)
	}
	for key, v := range doc {
		k := strings.TrimSpace(key)
		for _, bad := range customForbiddenKeys {
			if strings.EqualFold(k, bad) {
				return fmt.Errorf("the %s protocol is never run for custom templates", bad)
			}
		}
		if strings.EqualFold(k, "self-contained") {
			if b, ok := v.(bool); !ok || b {
				return fmt.Errorf("self-contained templates are never run for custom templates")
			}
		}
	}
	return nil
}
