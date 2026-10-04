// Package tenablesc is the sensor's Tenable Security Center (Tenable.sc)
// connector: the sensor, inside the customer network, pulls hosts,
// vulnerabilities and plugin metadata from Tenable.sc and pushes them to the
// platform as CTIS reports. The Tenable API keys never leave the sensor.
//
// Design: api docs/rfcs/RFC-047-tenable-sc-sensor-connector.md
// (github.com/openctemio/openctem).
package tenablesc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config file locations and environment variables.
const (
	// DefaultConfigPath is read when it exists and no path was given.
	DefaultConfigPath = "/etc/openctem/connectors/tenable-sc.yaml"
	// EnvConfig names the config file (the -tenable-sc-config flag wins).
	EnvConfig = "SENSOR_TENABLE_SC_CONFIG"

	// Single-instance shorthand (instance name "default").
	EnvURL            = "TENABLE_SC_URL"
	EnvAccessKeyFile  = "TENABLE_SC_ACCESS_KEY_FILE"
	EnvSecretKeyFile  = "TENABLE_SC_SECRET_KEY_FILE"
	EnvAccessKey      = "TENABLE_SC_ACCESS_KEY"
	EnvSecretKey      = "TENABLE_SC_SECRET_KEY"
	EnvCAFile         = "TENABLE_SC_CA_FILE"
	EnvRepositories   = "TENABLE_SC_REPOSITORIES"
	EnvOperations     = "TENABLE_SC_OPERATIONS"
	defaultInstance   = "default"
	configAPIVersion  = "openctem.io/connector-tenable-sc/v1"
	maxConfigBytes    = 1 << 20
	maxKeyBytes       = 256
	maxCAFileBytes    = 1 << 20
	maxInstances      = 16
	maxAllowListItems = 1000
)

// Operations an instance may allow.
const (
	OperationSync = "sync"
	OperationScan = "scan"
)

// Limit bounds (the config is clamped into them).
const (
	defaultPageSize         = 1000
	minPageSize             = 50
	maxPageSize             = 5000
	defaultMaxRecords       = 1_000_000
	maxMaxRecords           = 10_000_000
	defaultMaxResponseBytes = 64 << 20
	minMaxResponseBytes     = 1 << 20
	maxMaxResponseBytes     = 512 << 20
	defaultRPS              = 5
	maxRPS                  = 50
	defaultMaxTargets       = 512
	defaultMaxScanSeconds   = 28800
	maxMaxScanSeconds       = 7 * 24 * 3600
)

// ErrConfig marks a connector config that cannot be used. The sensor stops.
var ErrConfig = errors.New("tenable.sc connector config")

// Secret is a credential that never prints.
type Secret struct{ v string }

// String hides the value.
func (Secret) String() string { return "[redacted]" }

// GoString hides the value.
func (Secret) GoString() string { return "[redacted]" }

// MarshalText hides the value.
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Value returns the credential. Only the client calls it, to build the
// x-apikey header.
func (s Secret) Value() string { return s.v }

// Empty reports whether no value is set.
func (s Secret) Empty() bool { return s.v == "" }

// Config is the loaded connector config. Nil means the connector is off.
type Config struct {
	Instances []*Instance
}

// Instance returns the instance named name, or nil.
func (c *Config) Instance(name string) *Instance {
	if c == nil {
		return nil
	}
	for _, in := range c.Instances {
		if in.Name == name {
			return in
		}
	}
	return nil
}

// AllowsAnywhere reports whether any instance allows op.
func (c *Config) AllowsAnywhere(op string) bool {
	if c == nil {
		return false
	}
	for _, in := range c.Instances {
		if in.Allow.Operations[op] {
			return true
		}
	}
	return false
}

// Instance is one Tenable.sc the sensor may talk to.
type Instance struct {
	// Name is the only thing the platform knows about the instance.
	Name      string
	URL       *url.URL
	CAPEM     []byte   // nil: system roots
	Pins      [][]byte // SHA-256 of SubjectPublicKeyInfo; nil: no pin
	AccessKey Secret
	SecretKey Secret
	Allow     Allow
	Limits    Limits
}

// Allow is what the sensor owner lets the platform ask for.
type Allow struct {
	Operations        map[string]bool
	Repositories      []int
	ScanPolicies      []int
	ScanRepositories  []int
	ScanZones         []int
	MaxTargetsPerScan int
	MaxScanSeconds    int
}

// AllowsRepository reports whether id may be read.
func (a Allow) AllowsRepository(id int) bool { return slices.Contains(a.Repositories, id) }

// Limits bound what one command may read.
type Limits struct {
	PageSize          int
	MaxRecords        int
	MaxResponseBytes  int64
	RequestsPerSecond float64
}

// LoadOptions says where the config comes from. Zero values read the
// process environment and the default path.
type LoadOptions struct {
	// Path is the -tenable-sc-config flag; "" falls back to EnvConfig, then
	// DefaultConfigPath when that file exists.
	Path string
	// DefaultPath overrides DefaultConfigPath (tests).
	DefaultPath string
	// LookupEnv overrides os.LookupEnv (tests).
	LookupEnv func(string) (string, bool)
}

// Load reads the connector config. It returns (nil, warnings, nil) when the
// connector is not configured, and an error wrapping ErrConfig when a config
// exists but cannot be used (the sensor must stop: fail closed).
func Load(opts LoadOptions) (*Config, []string, error) {
	env := opts.LookupEnv
	if env == nil {
		env = os.LookupEnv
	}
	getenv := func(k string) string { v, _ := env(k); return strings.TrimSpace(v) }
	defPath := opts.DefaultPath
	if defPath == "" {
		defPath = DefaultConfigPath
	}

	path, explicit := strings.TrimSpace(opts.Path), true
	if path == "" {
		path = getenv(EnvConfig)
	}
	if path == "" {
		explicit = false
		if _, err := os.Stat(defPath); err == nil {
			path = defPath
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s: %v", ErrConfig, defPath, err)
		}
	}
	envURL := getenv(EnvURL)

	switch {
	case path != "" && envURL != "":
		return nil, nil, fmt.Errorf("%w: both a config file (%s) and %s are set; use one", ErrConfig, path, EnvURL)
	case path != "":
		cfg, warns, err := loadFile(path)
		if err != nil {
			if explicit || !errors.Is(err, os.ErrNotExist) {
				return nil, warns, err
			}
			return nil, warns, nil
		}
		return cfg, warns, nil
	case envURL != "":
		return loadEnv(getenv)
	default:
		return nil, nil, nil
	}
}

type fileConfig struct {
	APIVersion string         `yaml:"apiVersion"`
	Instances  []fileInstance `yaml:"instances"`
}

type fileInstance struct {
	Name          string     `yaml:"name"`
	URL           string     `yaml:"url"`
	CAFile        string     `yaml:"ca_file"`
	PinSPKISHA256 []string   `yaml:"pin_spki_sha256"`
	AccessKeyFile string     `yaml:"access_key_file"`
	SecretKeyFile string     `yaml:"secret_key_file"`
	Allow         fileAllow  `yaml:"allow"`
	Limits        fileLimits `yaml:"limits"`
}

type fileAllow struct {
	Operations        []string `yaml:"operations"`
	Repositories      []int    `yaml:"repositories"`
	ScanPolicies      []int    `yaml:"scan_policies"`
	ScanRepositories  []int    `yaml:"scan_repositories"`
	ScanZones         []int    `yaml:"scan_zones"`
	MaxTargetsPerScan int      `yaml:"max_targets_per_scan"`
	MaxScanSeconds    int      `yaml:"max_scan_seconds"`
}

type fileLimits struct {
	PageSize          int     `yaml:"page_size"`
	MaxRecords        int     `yaml:"max_records"`
	MaxResponseBytes  int64   `yaml:"max_response_bytes"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
}

func loadFile(path string) (*Config, []string, error) {
	data, err := readGuarded(path, maxConfigBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s does not exist: %w", ErrConfig, path, err)
		}
		return nil, nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, fmt.Errorf("%w: %s is empty", ErrConfig, path)
	}
	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrConfig, path, err)
	}
	if fc.APIVersion != configAPIVersion {
		return nil, nil, fmt.Errorf("%w: %s: apiVersion must be %q", ErrConfig, path, configAPIVersion)
	}
	if len(fc.Instances) == 0 {
		return nil, nil, fmt.Errorf("%w: %s: no instances", ErrConfig, path)
	}
	if len(fc.Instances) > maxInstances {
		return nil, nil, fmt.Errorf("%w: %s: at most %d instances", ErrConfig, path, maxInstances)
	}
	cfg := &Config{}
	var warns []string
	for i := range fc.Instances {
		in, w, err := buildInstance(&fc.Instances[i])
		warns = append(warns, w...)
		if err != nil {
			return nil, warns, fmt.Errorf("%w: %s: instance %d: %v", ErrConfig, path, i+1, err)
		}
		if cfg.Instance(in.Name) != nil {
			return nil, warns, fmt.Errorf("%w: %s: duplicate instance name %q", ErrConfig, path, in.Name)
		}
		cfg.Instances = append(cfg.Instances, in)
	}
	return cfg, warns, nil
}

func loadEnv(getenv func(string) string) (*Config, []string, error) {
	fi := fileInstance{
		Name:          defaultInstance,
		URL:           getenv(EnvURL),
		CAFile:        getenv(EnvCAFile),
		AccessKeyFile: getenv(EnvAccessKeyFile),
		SecretKeyFile: getenv(EnvSecretKeyFile),
	}
	repos, err := parseIntList(getenv(EnvRepositories))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrConfig, EnvRepositories, err)
	}
	fi.Allow.Repositories = repos
	fi.Allow.Operations = []string{OperationSync}
	if ops := getenv(EnvOperations); ops != "" {
		fi.Allow.Operations = splitList(ops)
	}
	var warns []string
	var rawAccess, rawSecret string
	if fi.AccessKeyFile == "" {
		if rawAccess = getenv(EnvAccessKey); rawAccess != "" {
			warns = append(warns, EnvAccessKey+" is set: environment values leak more easily than files; prefer "+EnvAccessKeyFile)
		}
	}
	if fi.SecretKeyFile == "" {
		if rawSecret = getenv(EnvSecretKey); rawSecret != "" {
			warns = append(warns, EnvSecretKey+" is set: environment values leak more easily than files; prefer "+EnvSecretKeyFile)
		}
	}
	in, w, err := buildInstanceWithKeys(&fi, rawAccess, rawSecret)
	warns = append(warns, w...)
	if err != nil {
		return nil, warns, fmt.Errorf("%w: environment: %v", ErrConfig, err)
	}
	return &Config{Instances: []*Instance{in}}, warns, nil
}

func buildInstance(fi *fileInstance) (*Instance, []string, error) {
	return buildInstanceWithKeys(fi, "", "")
}

var instanceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func buildInstanceWithKeys(fi *fileInstance, rawAccess, rawSecret string) (*Instance, []string, error) {
	var warns []string
	name := strings.TrimSpace(fi.Name)
	if !instanceNameRE.MatchString(name) {
		return nil, nil, fmt.Errorf("name %q: lowercase letters, digits, '.', '_', '-' (at most 63)", name)
	}
	u, err := parseBaseURL(fi.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", name, err)
	}
	in := &Instance{Name: name, URL: u}

	if fi.CAFile != "" {
		pem, err := readGuarded(fi.CAFile, maxCAFileBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: ca_file: %v", name, err)
		}
		if !bytes.Contains(pem, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, nil, fmt.Errorf("%s: ca_file %s holds no PEM certificate", name, fi.CAFile)
		}
		in.CAPEM = pem
	}
	for _, p := range fi.PinSPKISHA256 {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
		if err != nil || len(b) != sha256.Size {
			return nil, nil, fmt.Errorf("%s: pin_spki_sha256 %q is not a base64 SHA-256", name, p)
		}
		in.Pins = append(in.Pins, b)
	}

	access, err := keyValue(fi.AccessKeyFile, rawAccess, "access key")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", name, err)
	}
	secret, err := keyValue(fi.SecretKeyFile, rawSecret, "secret key")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", name, err)
	}
	in.AccessKey, in.SecretKey = Secret{access}, Secret{secret}

	allow, err := buildAllow(fi.Allow)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: allow: %v", name, err)
	}
	in.Allow = allow
	in.Limits = buildLimits(fi.Limits)
	return in, warns, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("url: %v", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("url must use https")
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("url must be https://host[:port][/path] with no user, query or fragment")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/rest")
	return u, nil
}

// keyChars: what an API key may contain. Anything else could break the
// x-apikey header (';', '=', spaces, CR/LF).
var keyChars = regexp.MustCompile(`^[A-Za-z0-9_\-]+$`)

func keyValue(file, raw, what string) (string, error) {
	v := raw
	if file != "" {
		b, err := readGuarded(file, maxKeyBytes)
		if err != nil {
			return "", fmt.Errorf("%s file: %v", what, err)
		}
		v = string(b)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%s is required (a key file)", what)
	}
	if len(v) > maxKeyBytes || !keyChars.MatchString(v) {
		return "", fmt.Errorf("%s has characters an API key cannot have", what)
	}
	return v, nil
}

func buildAllow(fa fileAllow) (Allow, error) {
	a := Allow{Operations: map[string]bool{}}
	if len(fa.Operations) == 0 {
		return a, errors.New("operations is required (sync and/or scan)")
	}
	for _, op := range fa.Operations {
		op = strings.ToLower(strings.TrimSpace(op))
		switch op {
		case OperationSync, OperationScan:
			a.Operations[op] = true
		default:
			return a, fmt.Errorf("unknown operation %q (sync, scan)", op)
		}
	}
	var err error
	if a.Repositories, err = idList("repositories", fa.Repositories); err != nil {
		return a, err
	}
	if len(a.Repositories) == 0 {
		return a, errors.New("repositories is required: nothing is read without it")
	}
	if a.ScanPolicies, err = idList("scan_policies", fa.ScanPolicies); err != nil {
		return a, err
	}
	if a.ScanRepositories, err = idList("scan_repositories", fa.ScanRepositories); err != nil {
		return a, err
	}
	if a.ScanZones, err = zoneList(fa.ScanZones); err != nil {
		return a, err
	}
	if a.Operations[OperationScan] && (len(a.ScanPolicies) == 0 || len(a.ScanRepositories) == 0) {
		return a, errors.New("operation scan needs scan_policies and scan_repositories")
	}
	a.MaxTargetsPerScan = clampInt(fa.MaxTargetsPerScan, defaultMaxTargets, 1, 65536)
	a.MaxScanSeconds = clampInt(fa.MaxScanSeconds, defaultMaxScanSeconds, 600, maxMaxScanSeconds)
	return a, nil
}

func idList(field string, in []int) ([]int, error) {
	if len(in) > maxAllowListItems {
		return nil, fmt.Errorf("%s: at most %d entries", field, maxAllowListItems)
	}
	out := make([]int, 0, len(in))
	for _, v := range in {
		if v <= 0 {
			return nil, fmt.Errorf("%s: %d is not a Tenable id", field, v)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// zoneList: scan zone 0 is Tenable's "all zones" default and is allowed.
func zoneList(in []int) ([]int, error) {
	if len(in) > maxAllowListItems {
		return nil, fmt.Errorf("scan_zones: at most %d entries", maxAllowListItems)
	}
	out := make([]int, 0, len(in))
	for _, v := range in {
		if v < 0 {
			return nil, fmt.Errorf("scan_zones: %d is not a Tenable id", v)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

func buildLimits(fl fileLimits) Limits {
	l := Limits{
		PageSize:          clampInt(fl.PageSize, defaultPageSize, minPageSize, maxPageSize),
		MaxRecords:        clampInt(fl.MaxRecords, defaultMaxRecords, 1, maxMaxRecords),
		MaxResponseBytes:  fl.MaxResponseBytes,
		RequestsPerSecond: fl.RequestsPerSecond,
	}
	switch {
	case l.MaxResponseBytes <= 0:
		l.MaxResponseBytes = defaultMaxResponseBytes
	case l.MaxResponseBytes < minMaxResponseBytes:
		l.MaxResponseBytes = minMaxResponseBytes
	case l.MaxResponseBytes > maxMaxResponseBytes:
		l.MaxResponseBytes = maxMaxResponseBytes
	}
	switch {
	case l.RequestsPerSecond <= 0:
		l.RequestsPerSecond = defaultRPS
	case l.RequestsPerSecond > maxRPS:
		l.RequestsPerSecond = maxRPS
	}
	return l
}

func clampInt(v, def, lo, hi int) int {
	switch {
	case v == 0:
		return def
	case v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

// readGuarded reads a file the sensor owner wrote, refusing one that anyone
// on the host may change (the platform must not be able to influence it, and
// neither may another local user).
func readGuarded(path string, limit int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("%s is world-writable; make it writable by its owner only", path)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	f, err := os.Open(path) //nolint:gosec // owner-configured path, checked above
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, f := range splitList(s) {
		v, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", f)
		}
		out = append(out, v)
	}
	return out, nil
}
