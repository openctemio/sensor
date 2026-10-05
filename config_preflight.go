package main

// Preflight checks of this sensor's own configuration, reported to the
// platform's Setup & health checklist through the SDK's config report
// (api docs/rfcs/RFC-033-sensor-manifest.md, "Config report"):
//
//   - an unknown key in the -config file (a typo such as max_job: was
//     dropped silently by the lax YAML decode);
//   - a ${VAR} in the -config file whose variable is unset (it became "");
//   - a daemon that runs no platform commands (-daemon without
//     -enable-commands);
//   - a retired scanner name (gitleaks).
//
// They warn; none of them stops the sensor. Only names are reported, never
// a setting's value.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

// Check ids this sensor reports besides the SDK's.
const (
	checkFileUnknownKey    = "config.file_unknown_key"
	checkFileUnsetVar      = "config.file_unset_var"
	checkCommandsDisabled  = "config.commands_disabled"
	checkToolRetired       = "config.tool_retired"
	maxConfigFindings      = 32
	configFindingNameLimit = 64
)

// configFindings is what loading the -config file noticed.
type configFindings struct {
	path        string
	unknownKeys []unknownKey
	unsetVars   []string
}

type unknownKey struct {
	key, suggestion string
	line            int
}

// legacyConfigKeys are keys of the pre-rename file that migrateConfigFile
// still reads.
var legacyConfigKeys = map[string]bool{"agent": true, "agent_id": true}

// yamlUnknownFieldRE matches yaml.v3's "line N: field X not found in type T".
var yamlUnknownFieldRE = regexp.MustCompile(`^line (\d+): field (\S+) not found in type `)

// loadConfigChecked is loadConfig plus what it noticed: unset ${VAR}s and
// keys the configuration does not know. The file is decoded as before (lax);
// the strict decode only finds the unknown keys.
func loadConfigChecked(path string, cfg *Config) (configFindings, error) {
	f := configFindings{path: path}
	data, err := os.ReadFile(path) // #nosec G304 -- the operator's own -config file
	if err != nil {
		return f, fmt.Errorf("read config: %w", err)
	}
	seen := map[string]bool{}
	expanded := os.Expand(string(data), func(name string) string {
		v, ok := os.LookupEnv(name)
		if !ok && !seen[name] && len(f.unsetVars) < maxConfigFindings {
			seen[name] = true
			f.unsetVars = append(f.unsetVars, name)
		}
		return v
	})
	sort.Strings(f.unsetVars)
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return f, fmt.Errorf("parse config: %w", err)
	}
	f.unknownKeys = unknownConfigKeys([]byte(expanded))
	return f, migrateConfigFile([]byte(expanded), cfg)
}

// unknownConfigKeys decodes data strictly into a throwaway Config and
// returns the keys it does not know, each with the closest known key.
func unknownConfigKeys(data []byte) []unknownKey {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var scratch Config
	err := dec.Decode(&scratch)
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return nil
	}
	known := configKeyNames(reflect.TypeOf(Config{}))
	var out []unknownKey
	for _, msg := range te.Errors {
		m := yamlUnknownFieldRE.FindStringSubmatch(msg)
		if m == nil || legacyConfigKeys[m[2]] || len(out) == maxConfigFindings {
			continue
		}
		var line int
		_, _ = fmt.Sscanf(m[1], "%d", &line)
		key := m[2]
		if len(key) > configFindingNameLimit {
			key = key[:configFindingNameLimit]
		}
		out = append(out, unknownKey{key: key, line: line, suggestion: settingsreg.Closest(key, known)})
	}
	return out
}

// configKeyNames are the yaml keys of t and its nested structs.
func configKeyNames(t reflect.Type) []string {
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name != "" && name != "-" {
				seen[name] = true
			}
			walk(f.Type)
		}
	}
	walk(t)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// warn prints what loading the file noticed (it was silent before).
func (f configFindings) warn(w io.Writer) {
	for _, u := range f.unknownKeys {
		msg := fmt.Sprintf("Warning: %s line %d: unknown key %q is ignored", f.path, u.line, u.key)
		if u.suggestion != "" {
			msg += fmt.Sprintf("; did you mean %q?", u.suggestion)
		}
		_, _ = fmt.Fprintln(w, msg)
	}
	for _, v := range f.unsetVars {
		_, _ = fmt.Fprintf(w, "Warning: %s uses ${%s}, which is not set; it was replaced by an empty value\n", f.path, v)
	}
}

// report records the findings as config report checks.
func (f configFindings) report(kit *sensorkit.Kit) {
	for _, u := range f.unknownKeys {
		params := map[string]core.ConfigParam{"key": core.ParamName(u.key), "line": core.ParamInt(int64(u.line))}
		if strings.HasPrefix(f.path, "/") {
			params["path"] = core.ParamPath(f.path)
		}
		summary := fmt.Sprintf("unknown key %s is ignored", u.key)
		if u.suggestion != "" {
			params["suggestion"] = core.ParamName(u.suggestion)
			summary += "; did you mean " + u.suggestion + "?"
		}
		kit.ReportCheck(core.ConfigCheck{ID: checkFileUnknownKey, Status: core.CheckWarn, Code: "unknown_key",
			Params: params, Summary: summary})
	}
	for _, v := range f.unsetVars {
		params := map[string]core.ConfigParam{"name": core.ParamName(v)}
		if strings.HasPrefix(f.path, "/") {
			params["path"] = core.ParamPath(f.path)
		}
		kit.ReportCheck(core.ConfigCheck{ID: checkFileUnsetVar, Status: core.CheckWarn, Code: "unset_var",
			Params: params, Keys: []string{v}, Summary: "${" + v + "} in the configuration file is not set"})
	}
}

// reportDaemonChecks records the daemon's own checks: commands off, and
// retired scanner names in the configuration.
func reportDaemonChecks(kit *sensorkit.Kit, cfg *Config, standalone bool, w io.Writer) {
	if !cfg.Sensor.EnableCommands && !standalone {
		_, _ = fmt.Fprintln(w, "Warning: -daemon without -enable-commands runs no platform scans; add -enable-commands (or sensor.enable_commands: true)")
		kit.ReportCheck(core.ConfigCheck{ID: checkCommandsDisabled, Status: core.CheckWarn, Code: "daemon_without_commands",
			Summary: "the daemon runs without -enable-commands: the platform's scans never run here"})
	}
	for _, s := range cfg.Scanners {
		if canon := core.CanonicalScannerName(s.Name); canon != s.Name && s.Name != "" {
			kit.ReportCheck(core.ConfigCheck{ID: checkToolRetired, Status: core.CheckWarn, Code: "retired_name",
				Params:  map[string]core.ConfigParam{"name": core.ParamName(s.Name), "replacement": core.ParamName(canon)},
				Keys:    []string{"SENSOR_TOOLS"},
				Summary: s.Name + " was replaced by " + canon})
		}
	}
}

// sensorSettings registers the settings this sensor reads besides the
// SDK's, so the config report lists their presence and unknown SENSOR_*
// names can be told apart from real ones.
func sensorSettings() *settingsreg.Registry {
	r := settingsreg.New()
	sensorkit.RegisterSDKSettings(r)
	s := func(name string, typ settingsreg.Type, group, desc string) settingsreg.Setting {
		return settingsreg.Setting{Name: name, Type: typ, Group: group, Description: desc}
	}
	secret := func(name, group, desc string) settingsreg.Setting {
		return settingsreg.Setting{Name: name, Type: settingsreg.String, Group: group, Description: desc, Secret: true}
	}
	r.Register(
		s("REGION", settingsreg.String, "platform", "Deployment region reported to the platform."),
		s("SENSOR_SCAN_ROOTS", settingsreg.List, "policy", "Directories dispatched code scans may read (the scan workspace)."),
		s("SENSOR_DNS_RESOLVERS", settingsreg.List, "network", "DNS resolvers for the recon tools (default: the system resolvers)."),
		s("SENSOR_CONTENT", settingsreg.Enum, "content", "Managed scanner content: on (default) or off."),
		settingsreg.Setting{Name: "SENSOR_CONTENT_DIR", Type: settingsreg.Path, Group: "content", Default: "$HOME/.openctem/content",
			Description: "Where managed content is kept. Mount a persistent volume (the templates use /var/lib/openctem/content)."},
		s("SENSOR_CONTENT_REFRESH_INTERVAL", settingsreg.Duration, "content", "How often content is refreshed (10m-720h; default 6h)."),
		s("SENSOR_CONTENT_KEEP", settingsreg.Int, "content", "Previous content versions kept (0-10; default 1)."),
		s("SENSOR_CONTENT_NUCLEI_TEMPLATES_URL", settingsreg.URL, "content", "nuclei templates archive URL."),
		s("SENSOR_CONTENT_NUCLEI_TEMPLATES_CHECKSUMS_URL", settingsreg.URL, "content", "nuclei templates checksums URL."),
		s("SENSOR_CONTENT_NUCLEI_TEMPLATES_LATEST_URL", settingsreg.URL, "content", "nuclei templates latest-release URL."),
		s("SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION", settingsreg.String, "content", "Pinned nuclei templates version."),
		s("SENSOR_CONTENT_NUCLEI_TEMPLATES_SHA256", settingsreg.String, "content", "Expected sha256 of the nuclei templates archive."),
		s("SENSOR_CONTENT_NUCLEI_TEMPLATES_DIR", settingsreg.Path, "content", "Pre-installed nuclei templates directory."),
		s("SENSOR_CONTENT_NUCLEI_MIN_TEMPLATES", settingsreg.Int, "content", "Fewest templates a nuclei templates release may have."),
		s("SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS", settingsreg.Int, "content", "Most templates that may fail to load."),
		s("SENSOR_CONTENT_SEMGREP_RULESETS", settingsreg.List, "content", "semgrep rulesets to fetch."),
		s("SENSOR_CONTENT_SEMGREP_REGISTRY_URL", settingsreg.URL, "content", "semgrep registry URL."),
		s("SENSOR_CONTENT_SEMGREP_RULES_PATH", settingsreg.Path, "content", "Local semgrep rules."),
		s("SENSOR_CONTENT_SEMGREP_SKIP_CHECK", settingsreg.Bool, "content", "Skip the semgrep rules check."),
		s("SENSOR_CONTENT_TRIVY_DB_REPOSITORY", settingsreg.String, "content", "trivy DB OCI repository."),
		s("SENSOR_CONTENT_TRIVY_JAVA_DB", settingsreg.Bool, "content", "Also fetch the trivy Java DB."),
		s("SENSOR_CONTENT_TRIVY_JAVA_DB_REPOSITORY", settingsreg.String, "content", "trivy Java DB OCI repository."),
		s("SENSOR_NUCLEI_MAX_RATE_LIMIT", settingsreg.Int, "tools", "Cap on nuclei's requests per second."),
		s("SENSOR_NUCLEI_MAX_CONCURRENCY", settingsreg.Int, "tools", "Cap on nuclei's template concurrency."),
		s("SENSOR_NUCLEI_MAX_BULK_SIZE", settingsreg.Int, "tools", "Cap on nuclei's hosts per template."),
		s("TRIVY_CACHE_DIR", settingsreg.Path, "tools", "trivy cache directory (needs a writable path on a read-only root filesystem)."),
		s("TRIVY_USERNAME", settingsreg.String, "tools", "Private registry user for trivy image scans."),
		secret("TRIVY_PASSWORD", "tools", "Private registry password for trivy image scans."),
		s("SENSOR_TENABLE_SC_CONFIG", settingsreg.Path, "connector", "Tenable.sc connector configuration file."),
		s("TENABLE_SC_URL", settingsreg.URL, "connector", "Tenable.sc URL (shorthand configuration)."),
		s("TENABLE_SC_CA_FILE", settingsreg.Path, "connector", "Tenable.sc private CA file."),
		s("TENABLE_SC_REPOSITORIES", settingsreg.List, "connector", "Tenable.sc repositories to pull."),
		s("TENABLE_SC_OPERATIONS", settingsreg.List, "connector", "Tenable.sc operations allowed."),
		secret("TENABLE_SC_ACCESS_KEY", "connector", "Tenable.sc API access key."),
		secret("TENABLE_SC_SECRET_KEY", "connector", "Tenable.sc API secret key."),
		s("TENABLE_SC_ACCESS_KEY_FILE", settingsreg.Path, "connector", "File holding the Tenable.sc access key."),
		s("TENABLE_SC_SECRET_KEY_FILE", settingsreg.Path, "connector", "File holding the Tenable.sc secret key."),
	)
	return r
}
