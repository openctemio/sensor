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
//   - the rule catalog (rules[]): one entry per template, with the
//     template's revision as the sensor ran it (content_sha256, from the
//     template-digest the sensor annotated each result with) and its place
//     in its content pack (content_path). Every finding names its template
//     by rule_ref and keeps rule_id equal to the rule's. A later re-check
//     counts only when it runs the same content;
//   - masking of credentials a matched URL carries in its user info or a
//     sensitive query parameter (?api_key=...), in every field of the
//     finding and of its asset.

var (
	digestRE    = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)
	sensitiveRE = regexp.MustCompile(`(?i)(pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth|session|sid|sig|signature|credential|private[_-]?key|client[_-]?secret|code)`)
	urlRE       = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s"'<>]+`)
)

// ruleSourceTenant is the rule source (extensions["io.openctem"].rule_source)
// of a rule of the organization's own templates.
const ruleSourceTenant = "tenant"

// ruleSourceKey is the io.openctem key naming who authored a rule.
const ruleSourceKey = "rule_source"

// templatePathKey is the source_extra key the importer copies nuclei's
// template-path into: a file on this sensor's disk, never sent (the rule's
// content_path names the template instead).
const templatePathKey = "template_path"

// maxProvenanceLine bounds a line read for template provenance.
const maxProvenanceLine = 1 << 20

type nucleiProvenance struct {
	Template       string `json:"template"`
	TemplatePath   string `json:"template-path"`
	TemplateDigest string `json:"template-digest"`
	// RuleSource is "tenant" on a result of one of the organization's own
	// templates (set by the sensor's nuclei wrapper, whose template id it
	// also prefixed with core.TenantRulePrefix).
	RuleSource string `json:"rule-source"`
}

// nucleiPostProcess applies the sensor's additions to a report the
// importer built from nuclei JSON Lines (data).
func nucleiPostProcess(r *ctis.Report, data []byte) {
	prov := provenanceByLine(data)
	rules := newRuleCatalog(r)
	for i := range r.Findings {
		f := &r.Findings[i]
		var p nucleiProvenance
		if f.Native != nil {
			p = prov[f.Native.RawRef]
		}
		delete(f.SourceExtra, templatePathKey)
		if len(f.SourceExtra) == 0 {
			f.SourceExtra = nil
		}
		rules.bind(f, p)
		if secrets := urlSecrets(f); len(secrets) > 0 {
			ctis.RedactSecretFinding(f, secrets...)
		}
	}
	for i := range r.Assets {
		r.Assets[i].Value = maskURL(r.Assets[i].Value)
		r.Assets[i].Name = maskURL(r.Assets[i].Name)
	}
}

// ruleCatalog builds the report's rules[]: one rule per template id.
type ruleCatalog struct {
	r      *ctis.Report
	byRule map[string]int // template id -> index in r.Rules
}

func newRuleCatalog(r *ctis.Report) *ruleCatalog {
	c := &ruleCatalog{r: r, byRule: map[string]int{}}
	for i, rule := range r.Rules {
		c.byRule[rule.RuleID] = i
	}
	return c
}

// bind names f's template by rule_ref, adding the template's rule on first
// use and filling in the revision and the place the result p carries when
// the rule has none yet. A finding without a template id names no rule.
func (c *ruleCatalog) bind(f *ctis.Finding, p nucleiProvenance) {
	if f.RuleID == "" {
		return
	}
	i, ok := c.byRule[f.RuleID]
	if !ok {
		i = len(c.r.Rules)
		c.r.Rules = append(c.r.Rules, ctis.Rule{
			ID:     "rule-" + strconv.Itoa(i+1),
			RuleID: f.RuleID,
			Name:   f.Title,
		})
		c.byRule[f.RuleID] = i
	}
	rule := &c.r.Rules[i]
	if m := digestRE.FindStringSubmatch(p.TemplateDigest); m != nil && rule.ContentSHA256 == "" {
		rule.ContentSHA256 = m[1]
	}
	if rule.ContentPath == "" {
		rule.ContentPath = templateRef(p.TemplatePath, p.Template)
	}
	if p.RuleSource == ruleSourceTenant {
		rule.Extensions.Set(ctis.OpenCTEMNamespace, ruleSourceKey, ruleSourceTenant)
	}
	f.RuleRef = rule.ID
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
		if json.Unmarshal(rec, &p) == nil && (p.Template != "" || p.TemplatePath != "" || p.TemplateDigest != "" || p.RuleSource != "") {
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
	texts = append(texts, f.Title, f.Message, f.Description)
	for _, e := range f.EvidenceItems {
		texts = append(texts, e.Text, e.Command)
		if e.HTTP != nil && e.HTTP.Request != nil {
			texts = append(texts, e.HTTP.Request.URL)
		}
	}
	if f.Web != nil {
		texts = append(texts, f.Web.URL)
	}
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

// templateRef is a template's place in its content pack:
// "<pack>/versions/<release>/<file>" when the absolute path abs names a
// release, else the file relative to nuclei's templates directory (abs when
// relative, else rel). A path that yields neither is "". Defence in depth:
// a path on this sensor's disk is never sent.
func templateRef(abs, rel string) string {
	if segs := strings.Split(filepath.ToSlash(abs), "/"); len(segs) > 0 {
		for i := 1; i+2 < len(segs); i++ {
			if segs[i] == "versions" && segs[i-1] != "" && segs[i+1] != "" {
				if r := strings.Join(segs[i+2:], "/"); filepath.IsLocal(r) {
					return segs[i-1] + "/versions/" + segs[i+1] + "/" + r
				}
			}
		}
	}
	if abs != "" && !filepath.IsAbs(abs) && filepath.IsLocal(abs) {
		return filepath.ToSlash(abs)
	}
	if rel != "" && len(rel) <= 512 && filepath.IsLocal(rel) && !strings.ContainsAny(rel, "\x00\r\n") {
		return filepath.ToSlash(rel)
	}
	return ""
}
