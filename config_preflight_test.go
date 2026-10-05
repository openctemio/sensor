package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sensor.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A typo in sensor.yaml was dropped silently; it is now named, with the key
// it was probably meant to be. The legacy agent: block is not flagged.
func TestLoadConfigChecked_UnknownKeyDidYouMean(t *testing.T) {
	p := writeConfig(t, "sensor:\n  name: s1\n  max_job: 4\nserver:\n  base_url: https://api\n  timout: 5s\nagent:\n  name: s1\n")
	var cfg Config
	f, err := loadConfigChecked(p, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sensor.Name != "s1" || cfg.API.BaseURL != "https://api" {
		t.Fatalf("the file must still load as before: %+v", cfg)
	}
	if len(f.unknownKeys) != 2 {
		t.Fatalf("unknown keys %+v", f.unknownKeys)
	}
	if u := f.unknownKeys[0]; u.key != "max_job" || u.suggestion != "max_jobs" || u.line != 3 {
		t.Fatalf("%+v", u)
	}
	if u := f.unknownKeys[1]; u.key != "timout" || u.suggestion != "timeout" {
		t.Fatalf("%+v", u)
	}
	var w bytes.Buffer
	f.warn(&w)
	if !strings.Contains(w.String(), `unknown key "max_job" is ignored; did you mean "max_jobs"?`) {
		t.Fatalf("warning: %s", w.String())
	}
}

// ${VAR} with VAR unset became "" silently; it is now named (a variable set
// to an empty value is the operator's choice and is not).
func TestLoadConfigChecked_UnsetVar(t *testing.T) {
	t.Setenv("CFG_TEST_EMPTY", "")
	_ = os.Unsetenv("CFG_TEST_MISSING")
	p := writeConfig(t, "server:\n  api_key: ${CFG_TEST_MISSING}\n  sensor_id: ${CFG_TEST_EMPTY}\n  base_url: $CFG_TEST_MISSING/x\n")
	var cfg Config
	f, err := loadConfigChecked(p, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.unsetVars) != 1 || f.unsetVars[0] != "CFG_TEST_MISSING" {
		t.Fatalf("unset vars %v", f.unsetVars)
	}
	if cfg.API.APIKey != "" {
		t.Fatal("expansion unchanged: an unset variable is empty")
	}
}

func standaloneKit(t *testing.T) *sensorkit.Kit {
	t.Helper()
	k, err := sensorkit.New(sensorkit.Options{Name: "t", Standalone: true, DisableCommands: true,
		StateDir: t.TempDir(), Settings: sensorSettings(), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The findings reach the config report as checks with names only: a value
// from the file (here a key under a misspelled name) never does.
func TestConfigFindings_ReportedWithoutValues(t *testing.T) {
	const canary = "CANARY-file-api-key-3141"
	_ = os.Unsetenv("CFG_TEST_MISSING")
	p := writeConfig(t, "server:\n  api_kee: "+canary+"\n  base_url: ${CFG_TEST_MISSING}\n")
	var cfg Config
	f, err := loadConfigChecked(p, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	k := standaloneKit(t)
	f.report(k)
	cfg.Scanners = []ScannerConfig{{Name: "gitleaks", Enabled: true}, {Name: "nuclei", Enabled: true}}
	var w bytes.Buffer
	reportDaemonChecks(k, &cfg, false, &w)
	r := k.ConfigReport()
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), canary) {
		t.Fatalf("a value from the file reached the report: %s", raw)
	}
	want := map[string]string{checkFileUnknownKey: "unknown_key", checkFileUnsetVar: "unset_var",
		checkCommandsDisabled: "daemon_without_commands", checkToolRetired: "retired_name"}
	for _, c := range r.Checks {
		if code, ok := want[c.ID]; ok && code == c.Code {
			delete(want, c.ID)
			if c.ID == checkFileUnknownKey && (c.Params["key"].Name != "api_kee" || c.Params["suggestion"].Name != "api_key") {
				t.Errorf("unknown key params %+v", c.Params)
			}
			if c.ID == checkToolRetired && c.Params["replacement"].Name != core.ScannerBetterleaks {
				t.Errorf("retired params %+v", c.Params)
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing checks %v in %s", want, raw)
	}
	if !strings.Contains(w.String(), "-daemon without -enable-commands") {
		t.Fatalf("warning: %s", w.String())
	}
}

// Every SENSOR_* / TENABLE_SC_* / TRIVY_* name this sensor reads is
// declared, so the unknown-variable check never flags one of ours.
func TestSensorSettings_DeclareEveryNameRead(t *testing.T) {
	reg := sensorSettings()
	re := regexp.MustCompile(`"((?:SENSOR|TENABLE_SC|TRIVY)_[A-Z0-9_]+)"`)
	skip := map[string]bool{"SENSOR_TEST_MAIN_ARGS": true, "SENSOR_API_KEY": true,
		// trivy's own variables the sensor sets for the trivy process.
		"TRIVY_DB_REPOSITORY": true, "TRIVY_DOWNLOAD_DB_ONLY": true, "TRIVY_DOWNLOAD_JAVA_DB_ONLY": true,
		"TRIVY_JAVA_DB_REPOSITORY": true, "TRIVY_OFFLINE_SCAN": true, "TRIVY_SKIP_DB_UPDATE": true,
		"TRIVY_SKIP_JAVA_DB_UPDATE": true}
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if !skip[m[1]] && !reg.Has(m[1]) {
				t.Errorf("%s reads %s, which sensorSettings does not declare", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
