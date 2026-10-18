package nuclei

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// customForbiddenKeys are the top-level template keys a custom template may
// not have: blocks that run code on the sensor (code, javascript, and flow,
// which is JavaScript run by nuclei's embedded interpreter), read its disk
// (file) or drive a browser (headless). Compared case-insensitively because
// nuclei also reads JSON templates, whose keys match any case.
//
// No local policy setting enables them: the sensor runs no code-executing
// custom template, whatever the platform signed. (A future opt-in for an
// organization's own sensors would be a local policy switch the network
// owner sets, never a job setting.)
var customForbiddenKeys = []string{"code", "javascript", "flow", "file", "headless"}

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
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("not a YAML template: %w", err)
	}
	// One document only: a second one is content this check would not read
	// but a parser might.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("a template must be one YAML document")
	}
	for key, v := range doc {
		k := strings.TrimSpace(key)
		for _, bad := range customForbiddenKeys {
			if strings.EqualFold(k, bad) {
				return fmt.Errorf("the %s block is never run for custom templates", bad)
			}
		}
		switch {
		case strings.EqualFold(k, "self-contained"):
			if b, ok := v.(bool); !ok || b {
				return fmt.Errorf("self-contained templates are never run for custom templates")
			}
		case strings.EqualFold(k, "workflows"):
			// nuclei resolves a workflow's template paths and tags against
			// its own template directory, not this job's signed set.
			return fmt.Errorf("custom templates may not run other templates (workflows)")
		}
	}
	if ref, ok := payloadFile(doc); ok {
		return fmt.Errorf("custom templates may not load payload files from the sensor's disk (%q)", ref)
	}
	return nil
}

// payloadFile finds a payload list loaded from a file (a string value under
// any request block's payloads): a custom template carries its payloads
// inline, so a path names a file on the sensor.
func payloadFile(doc map[string]any) (string, bool) {
	for _, v := range doc {
		blocks, _ := v.([]any)
		for _, b := range blocks {
			block, _ := b.(map[string]any)
			for k, p := range block {
				if !strings.EqualFold(strings.TrimSpace(k), "payloads") {
					continue
				}
				m, _ := p.(map[string]any)
				for _, val := range m {
					if s, ok := val.(string); ok {
						return s, true
					}
				}
			}
		}
	}
	return "", false
}
