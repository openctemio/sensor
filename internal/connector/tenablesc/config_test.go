package tenablesc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cfgFixture struct {
	dir, access, secret string
}

func newCfgFixture(t *testing.T) cfgFixture {
	t.Helper()
	dir := t.TempDir()
	fx := cfgFixture{dir: dir, access: filepath.Join(dir, "access"), secret: filepath.Join(dir, "secret")}
	writeFile(t, fx.access, testAccessKey+"\n", 0o600)
	writeFile(t, fx.secret, testSecretKey, 0o600)
	return fx
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func (fx cfgFixture) yaml(instanceBody string) string {
	return "apiVersion: openctem.io/connector-tenable-sc/v1\ninstances:\n  - name: sc-prod\n" +
		"    access_key_file: " + fx.access + "\n    secret_key_file: " + fx.secret + "\n" + instanceBody
}

func (fx cfgFixture) load(t *testing.T, content string) (*Config, error) {
	t.Helper()
	p := filepath.Join(fx.dir, "tenable-sc.yaml")
	writeFile(t, p, content, 0o640)
	cfg, _, err := Load(LoadOptions{Path: p, LookupEnv: noEnv})
	return cfg, err
}

func noEnv(string) (string, bool) { return "", false }

const goodBody = "    url: https://sc.corp.example/\n    allow:\n      operations: [sync]\n      repositories: [5, 7, 5]\n"

func TestLoad_Valid(t *testing.T) {
	fx := newCfgFixture(t)
	cfg, err := fx.load(t, fx.yaml(goodBody+"    limits:\n      page_size: 10\n      max_response_bytes: 1\n      requests_per_second: 999\n"))
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Instance("sc-prod")
	if in == nil || in.URL.String() != "https://sc.corp.example" {
		t.Fatalf("instance: %+v", in)
	}
	if in.AccessKey.Value() != testAccessKey || in.SecretKey.Value() != testSecretKey {
		t.Fatal("keys not read")
	}
	if got := in.Allow.Repositories; len(got) != 2 {
		t.Fatalf("repositories %v, want de-duplicated [5 7]", got)
	}
	if in.Limits.PageSize != minPageSize || in.Limits.MaxResponseBytes != minMaxResponseBytes || in.Limits.RequestsPerSecond != maxRPS {
		t.Fatalf("limits not clamped: %+v", in.Limits)
	}
	if !in.Allow.Operations[OperationSync] || in.Allow.Operations[OperationScan] {
		t.Fatal("operations")
	}
}

func TestLoad_Refusals(t *testing.T) {
	fx := newCfgFixture(t)
	cases := map[string]string{
		"unknown key":        fx.yaml(goodBody + "    insecure_skip_verify: true\n"),
		"http url":           fx.yaml("    url: http://sc.corp.example\n    allow:\n      operations: [sync]\n      repositories: [5]\n"),
		"url with user":      fx.yaml("    url: https://u:p@sc.corp.example\n    allow:\n      operations: [sync]\n      repositories: [5]\n"),
		"no repositories":    fx.yaml("    url: https://sc.corp.example\n    allow:\n      operations: [sync]\n"),
		"no operations":      fx.yaml("    url: https://sc.corp.example\n    allow:\n      repositories: [5]\n"),
		"unknown operation":  fx.yaml("    url: https://sc.corp.example\n    allow:\n      operations: [delete]\n      repositories: [5]\n"),
		"scan without lists": fx.yaml("    url: https://sc.corp.example\n    allow:\n      operations: [sync, scan]\n      repositories: [5]\n"),
		"negative repo":      fx.yaml("    url: https://sc.corp.example\n    allow:\n      operations: [sync]\n      repositories: [-1]\n"),
		"bad pin":            fx.yaml(goodBody + "    pin_spki_sha256: [\"abc\"]\n"),
		"bad name": "apiVersion: openctem.io/connector-tenable-sc/v1\ninstances:\n  - name: SC Prod\n" +
			"    access_key_file: " + fx.access + "\n    secret_key_file: " + fx.secret + "\n" + goodBody,
		"wrong apiVersion": strings.Replace(fx.yaml(goodBody), "connector-tenable-sc/v1", "connector-tenable-sc/v2", 1),
		"no instances":     "apiVersion: openctem.io/connector-tenable-sc/v1\ninstances: []\n",
		"empty file":       "   \n",
		"duplicate name":   fx.yaml(goodBody) + "  - name: sc-prod\n    access_key_file: " + fx.access + "\n    secret_key_file: " + fx.secret + "\n" + goodBody,
		"missing key file": strings.Replace(fx.yaml(goodBody), fx.secret, filepath.Join(fx.dir, "nope"), 1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := fx.load(t, content); !errors.Is(err, ErrConfig) {
				t.Fatalf("want ErrConfig, got %v", err)
			}
		})
	}
}

func TestLoad_WorldWritableRefused(t *testing.T) {
	fx := newCfgFixture(t)
	p := filepath.Join(fx.dir, "tenable-sc.yaml")
	writeFile(t, p, fx.yaml(goodBody), 0o666)
	if _, _, err := Load(LoadOptions{Path: p, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable config accepted: %v", err)
	}
	writeFile(t, p, fx.yaml(goodBody), 0o640)
	writeFile(t, fx.secret, testSecretKey, 0o666)
	if _, _, err := Load(LoadOptions{Path: p, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable key file accepted: %v", err)
	}
}

func TestLoad_KeyWithHeaderCharactersRefused(t *testing.T) {
	fx := newCfgFixture(t)
	writeFile(t, fx.secret, "abc; secretkey=evil", 0o600)
	if _, err := fx.load(t, fx.yaml(goodBody)); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

func TestLoad_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	// No path, default absent: connector off.
	cfg, _, err := Load(LoadOptions{DefaultPath: filepath.Join(dir, "absent.yaml"), LookupEnv: noEnv})
	if err != nil || cfg != nil {
		t.Fatalf("default absent: cfg %v err %v", cfg, err)
	}
	// An explicit path that is missing stops the sensor.
	if _, _, err := Load(LoadOptions{Path: filepath.Join(dir, "absent.yaml"), LookupEnv: noEnv}); !errors.Is(err, ErrConfig) {
		t.Fatalf("explicit missing path: %v", err)
	}
	env := func(k string) (string, bool) {
		if k == EnvConfig {
			return filepath.Join(dir, "absent.yaml"), true
		}
		return "", false
	}
	if _, _, err := Load(LoadOptions{DefaultPath: filepath.Join(dir, "x"), LookupEnv: env}); !errors.Is(err, ErrConfig) {
		t.Fatalf("env path missing: %v", err)
	}
}

func TestLoad_Env(t *testing.T) {
	fx := newCfgFixture(t)
	vals := map[string]string{
		EnvURL: "https://sc.corp.example", EnvAccessKeyFile: fx.access, EnvSecretKey: testSecretKey,
		EnvRepositories: "5, 7",
	}
	env := func(k string) (string, bool) { v, ok := vals[k]; return v, ok }
	cfg, warns, err := Load(LoadOptions{DefaultPath: filepath.Join(fx.dir, "absent"), LookupEnv: env})
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Instance("default")
	if in == nil || len(in.Allow.Repositories) != 2 || !in.Allow.Operations[OperationSync] || in.Allow.Operations[OperationScan] {
		t.Fatalf("env instance: %+v", in)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], EnvSecretKey) {
		t.Fatalf("raw key warning missing: %v", warns)
	}
	for _, w := range warns {
		if strings.Contains(w, testSecretKey) {
			t.Fatal("warning leaks the key")
		}
	}
	// Both a file and the env shorthand: refused.
	p := filepath.Join(fx.dir, "tenable-sc.yaml")
	writeFile(t, p, fx.yaml(goodBody), 0o640)
	if _, _, err := Load(LoadOptions{Path: p, LookupEnv: env}); !errors.Is(err, ErrConfig) {
		t.Fatalf("file + env accepted: %v", err)
	}
	// Env without repositories: refused.
	delete(vals, EnvRepositories)
	if _, _, err := Load(LoadOptions{DefaultPath: filepath.Join(fx.dir, "absent"), LookupEnv: env}); !errors.Is(err, ErrConfig) {
		t.Fatalf("env without repositories: %v", err)
	}
}
