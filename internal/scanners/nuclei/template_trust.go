package nuclei

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openctemio/sdk-go/pkg/core"
)

// maxCustomTemplateBytes bounds one custom template file read for the check
// (the SDK already refuses templates over 1 MiB).
const maxCustomTemplateBytes = 2 << 20

// CheckCustomTemplates refuses a custom-template directory with a template
// that uses a protocol the sensor never runs for custom templates or asks to
// be self-contained (core.CheckNucleiCustomTemplate: code, javascript, flow,
// file, headless, self-contained, workflows, payload files). The SDK runs
// the same check before it writes the templates; this one covers the
// directory the scanner actually reads. The platform refuses
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
	return core.CheckNucleiCustomTemplate(raw)
}
