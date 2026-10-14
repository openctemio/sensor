// Package flagcheck verifies that the command lines the recon scanners build
// use only flags the pinned tool version defines.
//
// The testdata/<tool>-<version>.help files are the tools' own `-h` output.
// ProjectDiscovery tools exit with "flag provided but not defined" on an
// unknown flag, so a wrong flag fails every run of that tool. Bump the help
// file together with the version the sensor image pins.
package flagcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// flagLine matches a help line that defines a flag: "   -l, -list string ..."
// or "   -silent  ...".
var flagLine = regexp.MustCompile(`^\s+(-[A-Za-z0-9][\w-]*)(?:,\s+(-[A-Za-z0-9][\w-]*))?`)

// Defined returns the flags a help text defines, short and long forms.
func Defined(help string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		m := flagLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, f := range m[1:] {
			if f != "" {
				out[f] = true
			}
		}
	}
	return out
}

// Testdata is the path of testdata/<name> next to the recon packages.
func Testdata(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", name)
}

// Check fails t for every argument in args that looks like a flag and is
// not defined in the help file. Values that start with '-' (a port range
// "-") are only skipped when the previous flag takes a value; callers pass
// such values as part of the expected args, so they are listed in values.
func Check(t *testing.T, helpName string, args []string, values ...string) {
	t.Helper()
	data, err := os.ReadFile(Testdata(helpName))
	if err != nil {
		t.Fatalf("read %s: %v", helpName, err)
	}
	defined := Defined(string(data))
	if len(defined) < 10 {
		t.Fatalf("%s: parsed only %d flags; is it a help file?", helpName, len(defined))
	}
	skip := map[string]bool{}
	for _, v := range values {
		skip[v] = true
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || skip[a] {
			continue
		}
		if !defined[a] {
			t.Errorf("%s does not define %s (args %q)", helpName, a, args)
		}
	}
}

// ManifestFlags checks that every option the manifest names a native flag
// for (x-octm-flag) reaches the tool's command line as that flag with the
// value set, and that the command line passes Check: the manifest, the
// argv and the pinned tool cannot drift. Each case is one scan's values;
// build resolves them and returns the arguments. Every option with a flag
// must be exercised by some case, and a value is checked as the token
// after the flag when want gives it ("" skips the value check: booleans).
func ManifestFlags(t *testing.T, helpName string, schema *core.SettingsSchema, cases []map[string]any, want map[string]string, build func(values map[string]any) []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, values := range cases {
		args := build(values)
		Check(t, helpName, args)
		for k := range values {
			p := schema.Property(k)
			if p == nil || p.Flag == "" {
				continue
			}
			seen[k] = true
			i := slices.Index(args, p.Flag)
			if i < 0 {
				t.Errorf("%s: %s missing from %q", k, p.Flag, args)
				continue
			}
			if v := want[k]; v != "" && (i+1 >= len(args) || args[i+1] != v) {
				t.Errorf("%s: %s %q, want %q (%q)", k, p.Flag, args[min(i+1, len(args)-1)], v, args)
			}
		}
	}
	for _, p := range schema.Properties {
		if p.Flag != "" && !seen[p.Name] {
			t.Errorf("%s (%s) is not exercised", p.Name, p.Flag)
		}
	}
}
