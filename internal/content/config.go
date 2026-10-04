package content

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Environment variables (all optional).
const (
	EnvContent            = "SENSOR_CONTENT"                  // "off" disables content management
	EnvDir                = "SENSOR_CONTENT_DIR"              // content root
	EnvInterval           = "SENSOR_CONTENT_REFRESH_INTERVAL" // e.g. "6h"
	EnvKeep               = "SENSOR_CONTENT_KEEP"             // previous versions kept
	EnvTrivyRepos         = "SENSOR_CONTENT_TRIVY_DB_REPOSITORY"
	EnvTrivyJavaDB        = "SENSOR_CONTENT_TRIVY_JAVA_DB"
	EnvTrivyJavaRepo      = "SENSOR_CONTENT_TRIVY_JAVA_DB_REPOSITORY"
	EnvNucleiURL          = "SENSOR_CONTENT_NUCLEI_TEMPLATES_URL"
	EnvNucleiChecksumsURL = "SENSOR_CONTENT_NUCLEI_TEMPLATES_CHECKSUMS_URL"
	EnvNucleiLatestURL    = "SENSOR_CONTENT_NUCLEI_TEMPLATES_LATEST_URL"
	EnvNucleiVersion      = "SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION"
	EnvNucleiSHA256       = "SENSOR_CONTENT_NUCLEI_TEMPLATES_SHA256"
	EnvNucleiDir          = "SENSOR_CONTENT_NUCLEI_TEMPLATES_DIR"
	EnvNucleiMin          = "SENSOR_CONTENT_NUCLEI_MIN_TEMPLATES"
	EnvNucleiMaxErrors    = "SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS"
	EnvSemgrepRulesets    = "SENSOR_CONTENT_SEMGREP_RULESETS"
	EnvSemgrepRegistry    = "SENSOR_CONTENT_SEMGREP_REGISTRY_URL"
	EnvSemgrepRulesPath   = "SENSOR_CONTENT_SEMGREP_RULES_PATH"
	EnvSemgrepSkipCheck   = "SENSOR_CONTENT_SEMGREP_SKIP_CHECK"
	defaultKeep           = 1
	defaultContentSubdir  = ".openctem/content"
)

// Settings are the host's content settings, from the environment.
type Settings struct {
	Enabled  bool
	Root     string
	Interval time.Duration
	Keep     int

	TrivyRepositories []string
	TrivyJavaDB       bool
	TrivyJavaRepo     string

	NucleiArchiveURL   string
	NucleiChecksumsURL string
	NucleiLatestURL    string
	NucleiTagURL       string
	NucleiVersion      string
	NucleiSHA256       string
	NucleiDir          string
	NucleiMin          int
	// NucleiMaxErrors: templates allowed to fail validation (0: the
	// default; -1 from "0" in the environment: none).
	NucleiMaxErrors int
	// NucleiMirror is true when the host operator set any nuclei URL. Only
	// then is the source trusted; the GitHub defaults filled in below are not.
	NucleiMirror bool

	SemgrepRulesets  []string
	SemgrepRegistry  string
	SemgrepRulesPath string
	SemgrepSkipCheck bool
}

// SettingsFromEnv reads the settings; lookup is os.LookupEnv in production.
func SettingsFromEnv(lookup func(string) (string, bool)) (Settings, error) {
	get := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	s := Settings{Enabled: true, Interval: DefaultInterval, Keep: defaultKeep}
	switch strings.ToLower(get(EnvContent)) {
	case "", "on", "true", "1":
	case "off", "false", "0":
		s.Enabled = false
	default:
		return s, fmt.Errorf("%s=%q: use on or off", EnvContent, get(EnvContent))
	}
	s.Root = get(EnvDir)
	if s.Root == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = os.TempDir()
		}
		s.Root = filepath.Join(home, defaultContentSubdir)
	}
	if v := get(EnvInterval); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 10*time.Minute || d > 30*24*time.Hour {
			return s, fmt.Errorf("%s=%q: a duration from 10m to 720h", EnvInterval, v)
		}
		s.Interval = d
	}
	if v := get(EnvKeep); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 10 {
			return s, fmt.Errorf("%s=%q: 0..10", EnvKeep, v)
		}
		s.Keep = n
	}
	s.TrivyRepositories = splitList(get(EnvTrivyRepos))
	for _, r := range s.TrivyRepositories {
		if _, err := ParseOCIRef(r); err != nil {
			return s, fmt.Errorf("%s: %w", EnvTrivyRepos, err)
		}
	}
	s.TrivyJavaDB = parseBool(get(EnvTrivyJavaDB))
	s.TrivyJavaRepo = get(EnvTrivyJavaRepo)

	s.NucleiArchiveURL = get(EnvNucleiURL)
	s.NucleiChecksumsURL = get(EnvNucleiChecksumsURL)
	s.NucleiLatestURL = get(EnvNucleiLatestURL)
	s.NucleiMirror = s.NucleiArchiveURL != "" || s.NucleiLatestURL != "" || s.NucleiChecksumsURL != ""
	if s.NucleiArchiveURL == "" {
		// Upstream: the GitHub release, its checksums file and the
		// releases API, unless the operator chose otherwise.
		s.NucleiArchiveURL = DefaultNucleiArchiveURL
		if s.NucleiChecksumsURL == "" {
			s.NucleiChecksumsURL = DefaultNucleiChecksumsURL
		}
		if s.NucleiLatestURL == "" {
			s.NucleiLatestURL = DefaultNucleiLatestURL
		}
		s.NucleiTagURL = DefaultNucleiTagURL
	}
	s.NucleiVersion = get(EnvNucleiVersion)
	s.NucleiSHA256 = strings.ToLower(get(EnvNucleiSHA256))
	if s.NucleiSHA256 != "" && !sha256HexRE.MatchString(s.NucleiSHA256) {
		return s, fmt.Errorf("%s: not a sha256 hex digest", EnvNucleiSHA256)
	}
	s.NucleiDir = get(EnvNucleiDir)
	if v := get(EnvNucleiMin); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return s, fmt.Errorf("%s=%q: a positive number", EnvNucleiMin, v)
		}
		s.NucleiMin = n
	}
	if v := get(EnvNucleiMaxErrors); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return s, fmt.Errorf("%s=%q: a number, 0 or more", EnvNucleiMaxErrors, v)
		}
		s.NucleiMaxErrors = n
		if n == 0 {
			s.NucleiMaxErrors = -1 // none allowed
		}
	}

	s.SemgrepRulesets = splitList(get(EnvSemgrepRulesets))
	s.SemgrepRegistry = get(EnvSemgrepRegistry)
	s.SemgrepRulesPath = get(EnvSemgrepRulesPath)
	s.SemgrepSkipCheck = parseBool(get(EnvSemgrepSkipCheck))
	return s, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseBool(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// Tools are the content-using tools a sensor runs, by canonical name.
type Tools struct {
	Trivy, Nuclei, Semgrep bool
}

// NewFromSettings builds a manager with a source per tool in use. Baked
// content is looked for in TRIVY_CACHE_DIR and $HOME/nuclei-templates.
func NewFromSettings(s Settings, tools Tools, verbose bool) (*Manager, error) {
	if !s.Enabled {
		return nil, nil
	}
	home, _ := os.UserHomeDir()
	var sources []Source
	if tools.Trivy {
		sources = append(sources, &TrivyDB{
			Repositories: s.TrivyRepositories, JavaDB: s.TrivyJavaDB, JavaRepository: s.TrivyJavaRepo,
			Resolver: &OCIResolver{
				Username: os.Getenv("TRIVY_USERNAME"), Password: os.Getenv("TRIVY_PASSWORD"),
				// Repositories set on the host are trusted (internal mirror).
				Trusted: len(s.TrivyRepositories) > 0,
			},
			BakedDir: os.Getenv("TRIVY_CACHE_DIR"), Root: s.Root,
		})
	}
	if tools.Nuclei {
		n := &NucleiTemplates{
			LatestURL: s.NucleiLatestURL, TagURL: s.NucleiTagURL, ArchiveURL: s.NucleiArchiveURL, ChecksumsURL: s.NucleiChecksumsURL,
			LocalDir: s.NucleiDir, Version: s.NucleiVersion, SHA256: s.NucleiSHA256, MinTemplates: s.NucleiMin,
			MaxTemplateErrors: s.NucleiMaxErrors,
			// A mirror set on the host is trusted; GitHub is reached SSRF-safe.
			Fetcher: &Fetcher{Trusted: s.NucleiMirror},
		}
		if home != "" {
			n.BakedDir = filepath.Join(home, "nuclei-templates")
		}
		sources = append(sources, n)
	}
	if tools.Semgrep {
		sources = append(sources, &SemgrepRules{
			Registry: s.SemgrepRegistry, Rulesets: s.SemgrepRulesets, LocalPath: s.SemgrepRulesPath,
			Fetcher: &Fetcher{Trusted: s.SemgrepRegistry != ""}, SkipCheck: s.SemgrepSkipCheck,
		})
	}
	if len(sources) == 0 {
		return nil, nil
	}
	keep := s.Keep
	if keep == 0 {
		keep = -1 // none
	}
	return New(Config{Root: s.Root, Interval: s.Interval, Keep: keep, Verbose: verbose}, sources...)
}
