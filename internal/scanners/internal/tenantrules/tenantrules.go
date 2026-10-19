// Package tenantrules prepares an organization's own rules for a scan that
// runs them with the platform's rules (api RFC-118, rule sources): the
// findings of an organization rule carry a tenant:-prefixed rule id
// (core.TenantRulePrefix), so they never collide with a platform rule of the
// same id, and an organization rule cannot replace a platform rule.
//
// Semgrep-format rules (opengrep, semgrep) cannot hold the prefix itself in
// their ids, so a run rewrites each id to a marker unique to the run, and the
// report's ids are mapped back afterwards (Rules.RestoreReport).
package tenantrules

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/core"
)

// maxRuleFileBytes bounds one rule file read (the SDK refuses templates
// over 1 MiB).
const maxRuleFileBytes = 2 << 20

// Rules is a run's rewritten copy of the organization's semgrep-format
// rules.
type Rules struct {
	// Dir holds the rewritten rule files.
	Dir string
	// prefix is the run's marker plus ".", prepended to every rule id.
	prefix string
}

// PrepareSemgrep copies every rule file in srcDir into a new temporary
// directory with each rule's id prefixed by a marker unique to this run.
// A file that is not a YAML document with a rules list of mappings that
// each have a string id is refused. srcDir is not changed.
func PrepareSemgrep(srcDir string) (*Rules, func(), error) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("organization rules: %w", err)
	}
	dir, err := os.MkdirTemp("", "tenant-rules-*")
	if err != nil {
		return nil, nil, fmt.Errorf("organization rules: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	r := &Rules{Dir: dir, prefix: "openctem-tenant-" + hex.EncodeToString(nonce[:]) + "."}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("organization rules: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			cleanup()
			return nil, nil, fmt.Errorf("organization rule file %q is not a regular file", e.Name())
		}
		info, err := e.Info()
		if err != nil || info.Size() > maxRuleFileBytes {
			cleanup()
			return nil, nil, fmt.Errorf("organization rule file %q is too large or unreadable", e.Name())
		}
		raw, err := os.ReadFile(filepath.Join(srcDir, e.Name())) //nolint:gosec // a file the executor wrote into its own temp dir
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("organization rule file %q: %w", e.Name(), err)
		}
		out, err := r.rewrite(raw)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("organization rule file %q: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), out, 0o600); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("organization rule file %q: %w", e.Name(), err)
		}
	}
	return r, cleanup, nil
}

// rewrite prefixes every rule id of one rule file.
func (r *Rules) rewrite(raw []byte) ([]byte, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a YAML rule file: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("a rule file must be one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("a rule file is a mapping with a rules list")
	}
	root := doc.Content[0]
	var rules *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			rules = root.Content[i+1]
		}
	}
	if rules == nil || rules.Kind != yaml.SequenceNode || len(rules.Content) == 0 {
		return nil, errors.New("a rule file needs a non-empty rules list")
	}
	for _, rule := range rules.Content {
		if rule.Kind != yaml.MappingNode {
			return nil, errors.New("every rule is a mapping")
		}
		found := false
		for i := 0; i+1 < len(rule.Content); i += 2 {
			if rule.Content[i].Value != "id" {
				continue
			}
			id := rule.Content[i+1]
			if id.Kind != yaml.ScalarNode || strings.TrimSpace(id.Value) == "" {
				return nil, errors.New("every rule needs a string id")
			}
			id.Value = r.prefix + id.Value
			id.Tag = "!!str"
			id.Style = yaml.DoubleQuotedStyle
			found = true
		}
		if !found {
			return nil, errors.New("every rule needs an id")
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RuleID maps a rule id from the run's report back: a rewritten id becomes
// core.TenantRuleID of the rule's own id; any other id is returned as is.
func (r *Rules) RuleID(id string) string {
	if r == nil || !strings.HasPrefix(id, r.prefix) {
		return id
	}
	return core.TenantRuleID(strings.TrimPrefix(id, r.prefix))
}

// RestoreReport maps every results[].check_id of a semgrep-format JSON
// report back (RuleID). A report that is not a JSON object is returned
// unchanged (the parser reports it); r == nil changes nothing.
func (r *Rules) RestoreReport(raw []byte) []byte {
	if r == nil || !bytes.Contains(raw, []byte(r.prefix)) {
		return raw
	}
	var rep map[string]json.RawMessage
	if json.Unmarshal(raw, &rep) != nil {
		return raw
	}
	var results []map[string]json.RawMessage
	if json.Unmarshal(rep["results"], &results) != nil {
		return raw
	}
	for _, res := range results {
		var id string
		if json.Unmarshal(res["check_id"], &id) != nil {
			continue
		}
		if mapped := r.RuleID(id); mapped != id {
			b, _ := json.Marshal(mapped)
			res["check_id"] = b
		}
	}
	b, err := json.Marshal(results)
	if err != nil {
		return raw
	}
	rep["results"] = b
	out, err := json.Marshal(rep)
	if err != nil {
		return raw
	}
	return out
}

// ForScan prepares a semgrep-format scan's custom rules (PrepareSemgrep)
// and returns a copy of opts whose CustomTemplateDir is the rewritten copy.
// Without custom rules it returns opts, nil rules and a no-op cleanup.
func ForScan(opts *core.ScanOptions) (*core.ScanOptions, *Rules, func(), error) {
	if opts == nil || opts.CustomTemplateDir == "" {
		return opts, nil, func() {}, nil
	}
	r, cleanup, err := PrepareSemgrep(opts.CustomTemplateDir)
	if err != nil {
		return nil, nil, nil, err
	}
	o := *opts
	o.CustomTemplateDir = r.Dir
	return &o, r, cleanup, nil
}

// Errors of a job whose rule sources contradict its rules.
var (
	ErrPlatformWithCustom = errors.New("the scan runs only platform rules but carries custom rules")
	ErrTenantWithoutRules = errors.New("the scan runs only the organization's rules but carries none")
)

// Select applies a scan's rule sources to its rule configs: the custom rule
// directory (custom, "" when none) and the platform's configs. It returns
// the configs to run: the custom rules when the organization's rules run,
// the platform's when the platform's run.
func Select(opts *core.ScanOptions, custom string, platform []string) ([]string, error) {
	rs := core.RuleSourcesBoth
	if opts != nil && opts.RuleSources != "" {
		rs = opts.RuleSources
	}
	var out []string
	switch {
	case custom != "" && !rs.Tenant():
		return nil, ErrPlatformWithCustom
	case custom == "" && !rs.Platform():
		return nil, ErrTenantWithoutRules
	case custom != "":
		out = append(out, custom)
	}
	if rs.Platform() {
		out = append(out, platform...)
	}
	return out, nil
}
