package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// recordingNuclei is a nuclei that writes its arguments, the run-signing
// certificate it was given and the template files it can load, then prints
// one match of the backup file check.
func recordingNuclei(t *testing.T) (bin, rec string) {
	t.Helper()
	rec = t.TempDir()
	bin = filepath.Join(t.TempDir(), "nuclei")
	script := `#!/bin/sh
printf '%s\n' "$@" > "` + rec + `/args"
printf '%s' "$` + nucleiUserCertEnv + `" > "` + rec + `/cert"
tdir=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-t" ]; then tdir="$2"; fi
  if [ "$1" = "-l" ]; then list="$2"; fi
  shift
done
ls "$tdir" > "` + rec + `/templates"
read -r target < "$list"
printf '{"template-id":"openctem-backup-file-signature","info":{"name":"b","severity":"info"},"host":"%s","matched-at":"%s"}\n' "$target" "$target"
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // a test script must be executable
		t.Fatal(err)
	}
	return bin, rec
}

// SECURITY: the platform's verification of a guessed backup or dump URL names
// the sensor's own check (scanner_config template_ids). The scan runs only
// that compiled-in check, as the run-signed copy, selected with -id, with the
// sensor's tag filters out of the way; an id that is not one of the
// sensor's own checks refuses the scan and starts nothing.
func TestScanRunsOnlyTheNamedBuiltinChecks(t *testing.T) {
	bin, rec := recordingNuclei(t)
	s := NewScanner()
	s.Binary = bin
	opts := &core.ScanOptions{Settings: scanSettings(t, map[string]any{
		"template_ids": []any{BackupFileSignatureID},
		// The platform sends the check's tag too (a safeguard for a sensor
		// that predates template_ids): this sensor selects by id.
		"tags": []any{"openctem"},
	})}
	sc, err := s.forScan(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sc.BuiltinIDs, []string{BackupFileSignatureID}) {
		t.Fatalf("builtin ids %v", sc.BuiltinIDs)
	}
	if len(s.BuiltinIDs) != 0 {
		t.Fatal("the scan's settings changed the scanner itself")
	}
	res, err := sc.scanTargetsDirect(context.Background(), []string{"https://app.example.com/backup.zip"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.RawOutput), BackupFileSignatureID) {
		t.Fatalf("output %q", res.RawOutput)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(rec, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	args := strings.Split(read("args"), "\n")
	if settingFlag(args, "-id") != BackupFileSignatureID {
		t.Errorf("no -id of the check in %q", args)
	}
	if slices.Contains(args, "-tags") || slices.Contains(args, "-severity") {
		t.Errorf("the sensor's own tag filters apply to a named check: %q", args)
	}
	if !slices.Contains(args, "-disable-unsigned-templates") {
		t.Errorf("signatures are not required: %q", args)
	}
	if !slices.Contains(args, "-etags") {
		t.Errorf("the tier's exclusions are missing: %q", args)
	}
	if got := read("templates"); got != BackupFileSignatureID+".yaml" {
		t.Errorf("nuclei could load %q, want only the named check", got)
	}
	if read("cert") == "" {
		t.Error("the run's signed copy is not trusted: no certificate given to nuclei")
	}
}

func TestScanRefusesIdsThatAreNotTheSensorsOwnChecks(t *testing.T) {
	for _, id := range []string{"cve-2021-44228", "exposed-panels", "no-such-check"} {
		_, err := NewScanner().forScan(&core.ScanOptions{Settings: scanSettings(t, map[string]any{"template_ids": []any{id}})})
		if err == nil || !strings.Contains(err.Error(), "not one of the sensor's own checks") {
			t.Errorf("%q: err %v, want a refusal", id, err)
		}
	}
	// Anything that is not an id never gets past the schema: no path, no URL.
	for _, id := range []string{"../etc/passwd", "a/b", "https://evil.example/t.yaml", "UPPER", ""} {
		if _, err := NewScanner().SettingsSchema().Resolve(core.SettingsLayer{Source: core.SettingSourceScan,
			Values: map[string]any{"template_ids": []any{id}}}); err == nil {
			t.Errorf("%q passed the schema", id)
		}
	}
}

// A scan of the sensor's own checks takes no custom templates.
func TestBuiltinScanRefusesCustomTemplates(t *testing.T) {
	s := NewScanner()
	s.Binary = "/nonexistent"
	sc := *s
	sc.BuiltinIDs = []string{BackupFileSignatureID}
	_, err := sc.execute(context.Background(), "", "", &core.ScanOptions{CustomTemplateDir: t.TempDir()}, "x")
	if err == nil {
		t.Fatal("a builtin scan carrying custom templates ran")
	}
}
