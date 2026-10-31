package main

// The install guides (scripts/install-guides.txt) must name only settings
// the sensor reads and flags it defines, so a renamed or removed setting
// fails here instead of in an operator's shell. Their release pins are
// checked by scripts/install-pins.sh.
//
// INSTALL_GUIDES_EXTRA (globs separated by ':') adds files outside this
// repository: the platform's CI runs these tests from the sensor's latest
// release against its install snippet templates
// (openctemio/openctem api/configs/sensor-products/sensor/*.tmpl).

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// guideOnlyNames are SENSOR_* names a guide may use that are not sensor
// settings: shell and Compose variables of the guides themselves, and the
// the settings the guides name only to explain them.
var guideOnlyNames = map[string]string{
	"SENSOR_VERSION":    "the release a guide installs (shell and .env variable)",
	"SENSOR_IMAGE":      "deploy/multi: image repository (Compose variable)",
	"SENSOR_VARIANT":    "deploy/multi: profile image suffix (Compose variable)",
	"SENSOR_MEM_LIMIT":  "deploy/multi: container memory ceiling (Compose variable)",
	"SENSOR_CPUS":       "deploy/multi: container CPU ceiling (Compose variable)",
	"SENSOR_PIDS_LIMIT": "deploy/multi: container process ceiling (Compose variable)",
	"SENSOR_TMP_SIZE":   "deploy/multi: /tmp size (Compose variable)",
	"SENSOR_JOB_ID":     "one platform command per run (a Kubernetes Job); not in the registry, documented as such",
	// Named to explain them, not to set them on the sensor.
	"SENSOR_KEY_TTL":              "a platform (API) setting the reference explains",
	"SENSOR_TENABLE_SC_CONFIG":    "removed: the connector moved out; the sensor prints a notice when it is set",
	"SENSOR_CONFIG_TEMPLATES_DIR": "a platform (API) setting the platform's snippet templates name in a comment",
}

var (
	guideEnvRE = regexp.MustCompile(`\bSENSOR_[A-Z0-9_]*[A-Z0-9]\b`)
	// A flag definition: fs.String("name", ...), flag.BoolVar(&v, "name", ...).
	flagDefRE = regexp.MustCompile(`\.(?:String|Bool|Int|Int64|Uint|Duration|Float64|Var|Func|BoolFunc|TextVar|StringVar|BoolVar|IntVar|DurationVar)\((?:&?[A-Za-z_.]+, *)?"([a-z][a-z0-9-]*)"`)
	// A single-dash flag on a command line (three characters or more, so
	// docker's -d, -e, -v and -it are not taken for the sensor's).
	guideFlagRE = regexp.MustCompile(`(?:^|\s)-([a-z][a-z0-9-]{1,})(?:=|\s|$|\))`)
)

// installGuides is every file scripts/install-guides.txt names.
func installGuides(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("scripts", "install-guides.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches, err := filepath.Glob(line)
		if err != nil {
			t.Fatalf("install-guides.txt: %q: %v", line, err)
		}
		if len(matches) == 0 {
			t.Errorf("install-guides.txt: %q matches no file", line)
		}
		out = append(out, matches...)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, glob := range filepath.SplitList(os.Getenv("INSTALL_GUIDES_EXTRA")) {
		matches, err := filepath.Glob(glob)
		if err != nil || len(matches) == 0 {
			t.Fatalf("INSTALL_GUIDES_EXTRA: %q matches no file (%v)", glob, err)
		}
		out = append(out, matches...)
	}
	return out
}

func TestInstallGuides_NameRegisteredSettings(t *testing.T) {
	reg := sensorSettings()
	for _, path := range installGuides(t) {
		data, err := os.ReadFile(path) // #nosec G304 -- a repository file listed in install-guides.txt
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, name := range guideEnvRE.FindAllString(line, -1) {
				if _, ok := guideOnlyNames[name]; ok || reg.Has(name) {
					continue
				}
				t.Errorf("%s:%d: %s is not a sensor setting (sensorSettings and the SDK registry do not have it): rename or remove it", path, i+1, name)
			}
		}
	}
}

// definedFlags is every flag name a FlagSet of the sensor defines, read from
// the source (the flags are declared inside main and the subcommands).
func definedFlags(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{"help": true, "h": true}
	for _, name := range append(append([]string{}, removedPlatformBoolFlags...), removedPlatformFlags...) {
		flags[name] = true
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- a source file of this package
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range flagDefRE.FindAllStringSubmatch(string(data), -1) {
			flags[m[1]] = true
		}
	}
	if len(flags) < 30 {
		t.Fatalf("found only %d flag definitions; the pattern no longer matches the source", len(flags))
	}
	return flags
}

func TestInstallGuides_NameDefinedFlags(t *testing.T) {
	flags := definedFlags(t)
	var unknown []string
	for _, path := range installGuides(t) {
		data, err := os.ReadFile(path) // #nosec G304 -- a repository file listed in install-guides.txt
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			// Only command lines of the sensor: the binary, or its image
			// followed by arguments.
			if !strings.Contains(line, "openctemio-sensor ") && !strings.Contains(line, "openctemio/sensor:") {
				continue
			}
			for _, m := range guideFlagRE.FindAllStringSubmatch(line, -1) {
				if len(m[1]) < 3 || flags[m[1]] {
					continue
				}
				unknown = append(unknown, path+":"+strconv.Itoa(i+1)+": -"+m[1])
			}
		}
	}
	sort.Strings(unknown)
	for _, u := range unknown {
		t.Errorf("%s is not a flag of the sensor", u)
	}
}
