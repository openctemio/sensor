package betterleaks

// The config of a scan with the organization's own rules (api RFC-118, rule
// sources). betterleaks reads one config; the sensor builds it from the
// organization's rule files:
//
//   - both: the organization's rules, extending the platform's rules (the
//     sensor's configured config, else the default rules). The organization
//     cannot disable or narrow the platform's rules: its files may not
//     carry [extend] settings other than useDefault = true, or a global
//     allowlist (it would hide the platform rules' findings too);
//   - tenant: the organization's rules alone, with its own [extend]
//     useDefault and allowlists if it wants them.
//
// Either way an [extend] path or url is refused (it would read a file on
// the sensor, or fetch one), and every organization rule id gets the
// tenant: prefix (core.TenantRulePrefix): its findings never collide with a
// platform rule's, and a rule of the same id can no longer replace a
// platform rule when the configs are merged.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/openctemio/sdk-go/pkg/core"
)

// maxRuleFileBytes bounds one organization rule file (the SDK refuses
// templates over 1 MiB).
const maxRuleFileBytes = 2 << 20

// customConfig writes the config of a scan with custom rules (see the file
// comment) into a new temporary directory and returns its path. platform is
// the platform's config file ("" = the default rules).
func customConfig(customDir string, rs core.RuleSources, platform string) (string, func(), error) {
	if !rs.Tenant() {
		return "", nil, errors.New("the scan runs only platform rules but carries custom rules")
	}
	entries, err := os.ReadDir(customDir)
	if err != nil {
		return "", nil, fmt.Errorf("organization rules: %w", err)
	}
	var names []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".toml" {
			continue
		}
		if !e.Type().IsRegular() {
			return "", nil, fmt.Errorf("organization rule file %q is not a regular file", e.Name())
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return "", nil, errors.New("the scan carries custom rules but no .toml rule file")
	}
	sort.Strings(names)
	files := make([][]byte, 0, len(names))
	for _, n := range names {
		info, err := os.Stat(filepath.Join(customDir, n))
		if err != nil || info.Size() > maxRuleFileBytes {
			return "", nil, fmt.Errorf("organization rule file %q is too large or unreadable", n)
		}
		raw, err := os.ReadFile(filepath.Join(customDir, n)) //nolint:gosec // a file the executor wrote into its own temp dir
		if err != nil {
			return "", nil, fmt.Errorf("organization rule file %q: %w", n, err)
		}
		files = append(files, raw)
	}
	cfg, err := buildConfig(files, rs, platform)
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "betterleaks-rules-*")
	if err != nil {
		return "", nil, fmt.Errorf("organization rules: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "rules.toml")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("organization rules: %w", err)
	}
	return path, cleanup, nil
}

// buildConfig merges the organization's rule files into one config for the
// rule sources rs (both or tenant; see the file comment).
func buildConfig(files [][]byte, rs core.RuleSources, platform string) ([]byte, error) {
	out := map[string]any{}
	var rules []map[string]any
	var extend map[string]any
	for i, raw := range files {
		var doc map[string]any
		if _, err := toml.Decode(string(raw), &doc); err != nil {
			return nil, fmt.Errorf("organization rule file %d: not a TOML config: %w", i+1, err)
		}
		for key, v := range doc {
			// betterleaks reads keys without regard to case.
			switch strings.ToLower(key) {
			case "title", "description", "minversion":
				// Descriptive; the merged config has its own.
			case "rules":
				found, err := tenantRules(v)
				if err != nil {
					return nil, fmt.Errorf("organization rule file %d: %w", i+1, err)
				}
				rules = append(rules, found...)
			case "extend":
				e, err := checkExtend(v, rs)
				if err != nil {
					return nil, fmt.Errorf("organization rule file %d: %w", i+1, err)
				}
				if rs == core.RuleSourcesTenant {
					extend = e
				}
			case "allowlist", "allowlists":
				if rs != core.RuleSourcesTenant {
					return nil, fmt.Errorf("organization rule file %d: a global %s would also hide the platform rules' findings; put it on the organization's own rules, or run only the organization's rules", i+1, key)
				}
				if _, dup := out[key]; dup {
					return nil, fmt.Errorf("organization rule file %d: %s set in more than one file", i+1, key)
				}
				out[key] = v
			default:
				return nil, fmt.Errorf("organization rule file %d: unknown key %q", i+1, key)
			}
		}
	}
	if len(rules) == 0 {
		return nil, errors.New("the organization's rule files define no rule")
	}
	out["title"] = "organization rules"
	out["rules"] = rules
	switch {
	case rs != core.RuleSourcesTenant && platform != "":
		out["extend"] = map[string]any{"path": platform}
	case rs != core.RuleSourcesTenant:
		out["extend"] = map[string]any{"useDefault": true}
	case extend != nil:
		out["extend"] = extend
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(out); err != nil {
		return nil, fmt.Errorf("organization rules: %w", err)
	}
	return buf.Bytes(), nil
}

// tenantRules reads a rules array and prefixes every rule id.
func tenantRules(v any) ([]map[string]any, error) {
	list, ok := v.([]map[string]any)
	if !ok {
		return nil, errors.New("rules must be an array of tables ([[rules]])")
	}
	out := make([]map[string]any, 0, len(list))
	for _, r := range list {
		idKey := ""
		for k := range r {
			if strings.EqualFold(k, "id") {
				idKey = k
			}
		}
		id, _ := r[idKey].(string)
		if idKey == "" || strings.TrimSpace(id) == "" {
			return nil, errors.New("every rule needs an id")
		}
		rule := make(map[string]any, len(r))
		for k, val := range r {
			rule[k] = val
		}
		delete(rule, idKey)
		rule["id"] = core.TenantRuleID(id)
		out = append(out, rule)
	}
	return out, nil
}

// checkExtend checks an organization file's [extend]: never a path or url;
// with both rule sources nothing but useDefault = true. It returns the
// table to keep for a tenant-only config.
func checkExtend(v any, rs core.RuleSources) (map[string]any, error) {
	e, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("extend must be a table")
	}
	for k, val := range e {
		switch strings.ToLower(k) {
		case "path", "url":
			return nil, fmt.Errorf("[extend] %s is not allowed: the organization's rules cannot load other files", k)
		case "usedefault":
			if b, ok := val.(bool); !ok || (!b && rs != core.RuleSourcesTenant) {
				return nil, errors.New("[extend] useDefault = false would drop the platform rules; run only the organization's rules instead")
			}
		case "disabledrules":
			if rs != core.RuleSourcesTenant {
				return nil, errors.New("[extend] disabledRules would disable platform rules; run only the organization's rules instead")
			}
		default:
			return nil, fmt.Errorf("[extend] %s is not supported", k)
		}
	}
	return e, nil
}
