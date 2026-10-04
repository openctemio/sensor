package nuclei

// The digest of the template that produced each result (api research 18,
// owner decision O6): a re-check of a finding counts only when it ran the
// same template content, so a finding must record which content found it.
// The release's version and archive digest (tool.properties.content) change
// with every release; a template's own digest changes only when that
// template does, so a release bump does not make every retest inconclusive.
//
// nuclei names the template file in each result (template-path) but does not
// hash it, and omits template-encoded for the official templates. The sensor
// hashes the file itself, while the run still holds its template version, and
// adds the digest to the result line as "template-digest". Only files inside
// the run's own template directories are read: template-path comes from the
// scanner's output, and a path outside them is left without a digest.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxTemplateBytes bounds a template file hashed for its digest (the largest
// official template is well under 1 MB).
const maxTemplateBytes = 4 << 20

// templateDigestKey is the result field the sensor adds; nuclei has none of
// that name, and one it emitted would be replaced.
const templateDigestKey = "template-digest"

// TemplateDigest returns "sha256:<hex>" of the template file at path when
// it resolves (symlinks included) to a regular file inside one of roots.
func TemplateDigest(path string, roots []string) (string, bool) {
	if path == "" || len(roots) == 0 {
		return "", false
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	inside := false
	for _, r := range roots {
		if r == "" {
			continue
		}
		rr, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(rr, real); err == nil && filepath.IsLocal(rel) {
			inside = true
			break
		}
	}
	if !inside {
		return "", false
	}
	raw, err := readRegular(real, maxTemplateBytes)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// resolveTemplatePath makes a template path nuclei printed absolute: an
// absolute path is kept, a relative one (nuclei prints paths relative to its
// templates directory) is taken under base.
func resolveTemplatePath(p, base string) string {
	if p == "" || filepath.IsAbs(p) || base == "" {
		return p
	}
	return filepath.Join(base, p)
}

// annotateTemplateDigests adds "template-digest" to every JSON result line
// whose template-path is a template file inside roots. Other lines (and
// output that is not JSON Lines) are returned unchanged; each file is hashed
// once per run.
func annotateTemplateDigests(output []byte, roots []string) []byte {
	if len(bytes.TrimSpace(output)) == 0 || len(roots) == 0 {
		return output
	}
	cache := map[string]string{}
	var out bytes.Buffer
	out.Grow(len(output) + 128)
	sc := bufio.NewScanner(bytes.NewReader(output))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	changed := false
	for sc.Scan() {
		line := sc.Bytes()
		if annotated, ok := annotateLine(line, roots, cache); ok {
			out.Write(annotated)
			changed = true
		} else {
			out.Write(line)
		}
		out.WriteByte('\n')
	}
	if sc.Err() != nil || !changed {
		return output
	}
	return out.Bytes()
}

func annotateLine(line []byte, roots []string, cache map[string]string) ([]byte, bool) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(trimmed, &fields) != nil {
		return nil, false
	}
	var path string
	if raw, ok := fields["template-path"]; !ok || json.Unmarshal(raw, &path) != nil || path == "" {
		return nil, false
	}
	digest, seen := cache[path]
	if !seen {
		digest, _ = TemplateDigest(path, roots)
		cache[path] = digest
	}
	if digest == "" {
		return nil, false
	}
	fields[templateDigestKey] = json.RawMessage(fmt.Sprintf("%q", digest))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(fields) != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

// templateRoots are the directories a run's templates may come from: the
// scanner's template directory (nuclei's own when none is set) and the
// platform's custom templates.
func (s *Scanner) templateRoots(customDir string) []string {
	var roots []string
	for _, t := range s.Templates {
		if fi, err := os.Stat(t); err == nil && fi.IsDir() {
			roots = append(roots, t)
		}
	}
	if s.TemplateDir != "" {
		roots = append(roots, s.TemplateDir)
	} else if d := GetTemplateDir(); d != "" {
		roots = append(roots, d)
	}
	if customDir = strings.TrimSpace(customDir); customDir != "" {
		roots = append(roots, customDir)
	}
	return roots
}
