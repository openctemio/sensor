package importparse

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// What the sensor adds to the importer's nuclei findings:
//
//   - the template provenance the sensor annotated each result with
//     (template-digest, set by the sensor, and the template path): a later
//     re-check counts only when it runs the same content;
//   - masking of credentials a matched URL carries in its user info or a
//     sensitive query parameter (?api_key=...), in every field of the
//     finding and of its asset.

var (
	digestRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sensitiveRE = regexp.MustCompile(`(?i)(pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|session|sid|sig|signature|credential|private[_-]?key|client[_-]?secret|code)`)
	urlRE       = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s"'<>]+`)
)

// maxProvenanceLine bounds a line read for template provenance.
const maxProvenanceLine = 1 << 20

type nucleiProvenance struct {
	Template       string `json:"template"`
	TemplateDigest string `json:"template-digest"`
}

// nucleiPostProcess applies the sensor's additions to a report the
// importer built from nuclei JSON Lines (data).
func nucleiPostProcess(r *ctis.Report, data []byte) {
	prov := provenanceByLine(data)
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Native != nil {
			if p, ok := prov[f.Native.RawRef]; ok {
				if f.Properties == nil {
					f.Properties = ctis.Properties{}
				}
				if digestRE.MatchString(p.TemplateDigest) {
					f.Properties["template_digest"] = p.TemplateDigest
				}
				if t := p.Template; t != "" && len(t) <= 512 && filepath.IsLocal(t) && !strings.ContainsAny(t, "\x00\r\n") {
					f.Properties["template_path"] = filepath.ToSlash(t)
				}
			}
		}
		if secrets := urlSecrets(f); len(secrets) > 0 {
			ctis.RedactSecretFinding(f, secrets...)
		}
	}
	for i := range r.Assets {
		r.Assets[i].Value = maskURL(r.Assets[i].Value)
		r.Assets[i].Name = maskURL(r.Assets[i].Name)
	}
}

// provenanceByLine maps the importer's raw reference of each JSON Lines
// record ("line N") to its template provenance.
func provenanceByLine(data []byte) map[string]nucleiProvenance {
	out := map[string]nucleiProvenance{}
	ln := 0
	for len(data) > 0 {
		ln++
		end := bytes.IndexByte(data, '\n')
		var rec []byte
		if end < 0 {
			rec, data = data, nil
		} else {
			rec, data = data[:end], data[end+1:]
		}
		rec = bytes.TrimSpace(rec)
		if len(rec) == 0 || len(rec) > maxProvenanceLine || !bytes.Contains(rec, []byte(`"template`)) {
			continue
		}
		var p nucleiProvenance
		if json.Unmarshal(rec, &p) == nil && (p.Template != "" || p.TemplateDigest != "") {
			out["line "+strconv.Itoa(ln)] = p
		}
	}
	return out
}

// urlSecrets are the credentials the URLs in a finding carry: user info
// and the values of sensitive query parameters.
func urlSecrets(f *ctis.Finding) []string {
	var texts []string
	if f.Location != nil {
		texts = append(texts, f.Location.Path)
	}
	texts = append(texts, f.Title, f.Message, f.Description, f.Evidence, f.AssetValue)
	var out []string
	for _, t := range texts {
		for _, raw := range urlRE.FindAllString(t, 16) {
			out = append(out, secretsOfURL(raw)...)
		}
	}
	return out
}

func secretsOfURL(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	if u.User != nil {
		out = append(out, u.User.String())
		if p, ok := u.User.Password(); ok && p != "" {
			out = append(out, p)
		}
	}
	for k, vs := range u.Query() {
		if !sensitiveRE.MatchString(k) {
			continue
		}
		for _, v := range vs {
			if len(v) >= 4 {
				out = append(out, v)
			}
		}
	}
	return out
}

// maskURL masks the credentials of a URL-valued asset value.
func maskURL(v string) string {
	for _, s := range secretsOfURL(v) {
		v = strings.ReplaceAll(v, s, ctis.MaskSecretMatch(s))
	}
	return v
}
