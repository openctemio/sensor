package main

import (
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// fakeEnv is an environment for migrateEnv.
type fakeEnv map[string]string

func (e fakeEnv) lookup(k string) (string, bool) { v, ok := e[k]; return v, ok }
func (e fakeEnv) set(k, v string) error          { e[k] = v; return nil }

func captureWarnings(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := legacyv1.Warn
	legacyv1.Warn = func(old, replacement, kind string) { got = append(got, kind+": "+old+" -> "+replacement) }
	t.Cleanup(func() { legacyv1.Warn = prev })
	return &got
}

// One test per renamed variable: the old name alone is applied to the new
// one, with a warning naming both.
func TestMigrateEnvMapsEachOldVariable(t *testing.T) {
	for _, r := range renamedEnv {
		t.Run(r.Old, func(t *testing.T) {
			warns := captureWarnings(t)
			env := fakeEnv{r.Old: "value-1", "API_URL": "https://api", "API_KEY": "k", "BOOTSTRAP_TOKEN": "b"}
			if err := migrateEnv(env.lookup, env.set); err != nil {
				t.Fatal(err)
			}
			if env[r.New] != "value-1" {
				t.Fatalf("%s = %q, want the value of %s", r.New, env[r.New], r.Old)
			}
			want := "environment: " + r.Old + " -> " + r.New
			if len(*warns) != 1 || (*warns)[0] != want {
				t.Fatalf("warnings = %v, want [%s]", *warns, want)
			}
			// Unrenamed settings are untouched.
			if env["API_URL"] != "https://api" || env["API_KEY"] != "k" || env["BOOTSTRAP_TOKEN"] != "b" {
				t.Fatalf("API_URL / API_KEY / BOOTSTRAP_TOKEN changed: %v", env)
			}
		})
	}
}

func TestMigrateEnvNewNameWinsWhenEqual(t *testing.T) {
	for _, r := range renamedEnv {
		t.Run(r.Old, func(t *testing.T) {
			warns := captureWarnings(t)
			env := fakeEnv{r.Old: "x", r.New: "x"}
			if err := migrateEnv(env.lookup, env.set); err != nil {
				t.Fatal(err)
			}
			if env[r.New] != "x" || len(*warns) != 1 {
				t.Fatalf("env %v warnings %v", env, *warns)
			}
		})
	}
}

// Old and new set to different values: refused, naming both, never values.
func TestMigrateEnvRefusesConflicts(t *testing.T) {
	for _, r := range renamedEnv {
		t.Run(r.Old, func(t *testing.T) {
			captureWarnings(t)
			env := fakeEnv{r.Old: "old-secret", r.New: "new-secret"}
			err := migrateEnv(env.lookup, env.set)
			if err == nil {
				t.Fatal("conflict must be refused")
			}
			msg := err.Error()
			if !strings.Contains(msg, r.Old) || !strings.Contains(msg, r.New) {
				t.Fatalf("error %q must name %s and %s", msg, r.Old, r.New)
			}
			if strings.Contains(msg, "secret") {
				t.Fatalf("error %q must not print values", msg)
			}
			if env[r.New] != "new-secret" {
				t.Fatal("a conflict must not overwrite the new value")
			}
		})
	}
}

func TestRenamedEnvTable(t *testing.T) {
	want := map[string]string{
		"AGENT_ID":                    "SENSOR_ID",
		"AGENT_NAME":                  "SENSOR_NAME",
		"AGENT_ALLOW_PRIVATE_TARGETS": "SENSOR_ALLOW_PRIVATE_TARGETS",
	}
	if len(renamedEnv) != len(want) {
		t.Fatalf("renamedEnv = %v", renamedEnv)
	}
	for _, r := range renamedEnv {
		if want[r.Old] != r.New {
			t.Errorf("%s -> %s, want %s", r.Old, r.New, want[r.Old])
		}
	}
}

func newFlags() (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("sensor", flag.ContinueOnError)
	id := fs.String("sensor-id", "", "")
	_ = fs.String("agent-id", "", "")
	return fs, id
}

func TestMigrateFlags(t *testing.T) {
	t.Run("old flag is applied with a warning", func(t *testing.T) {
		warns := captureWarnings(t)
		fs, id := newFlags()
		if err := fs.Parse([]string{"--agent-id", "s-1"}); err != nil {
			t.Fatal(err)
		}
		if err := migrateFlags(fs); err != nil {
			t.Fatal(err)
		}
		if *id != "s-1" {
			t.Fatalf("-sensor-id = %q", *id)
		}
		if len(*warns) != 1 || (*warns)[0] != "flag: -agent-id -> -sensor-id" {
			t.Fatalf("warnings = %v", *warns)
		}
	})
	t.Run("new flag alone", func(t *testing.T) {
		warns := captureWarnings(t)
		fs, id := newFlags()
		_ = fs.Parse([]string{"-sensor-id", "s-2"})
		if err := migrateFlags(fs); err != nil || *id != "s-2" || len(*warns) != 0 {
			t.Fatalf("id %q err %v warnings %v", *id, err, *warns)
		}
	})
	t.Run("conflict is refused", func(t *testing.T) {
		captureWarnings(t)
		fs, _ := newFlags()
		_ = fs.Parse([]string{"-sensor-id", "a", "-agent-id", "b"})
		err := migrateFlags(fs)
		if err == nil || !strings.Contains(err.Error(), "-agent-id") || !strings.Contains(err.Error(), "-sensor-id") {
			t.Fatalf("err = %v, want a conflict naming both flags", err)
		}
	})
}

func TestMigrateConfigFile(t *testing.T) {
	load := func(t *testing.T, yml string) (*Config, error) {
		t.Helper()
		var cfg Config
		path := t.TempDir() + "/c.yaml"
		if err := writeTestFile(path, yml); err != nil {
			t.Fatal(err)
		}
		err := loadConfig(path, &cfg)
		return &cfg, err
	}

	t.Run("pre-rename agent: block and server.agent_id", func(t *testing.T) {
		warns := captureWarnings(t)
		cfg, err := load(t, "agent:\n  name: edge-1\n  enable_commands: true\n  heartbeat_interval: 30s\nserver:\n  base_url: https://api\n  agent_id: s-1\n")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Sensor.Name != "edge-1" || !cfg.Sensor.EnableCommands || cfg.Sensor.HeartbeatInterval != 30*time.Second {
			t.Fatalf("agent: block not applied: %+v", cfg.Sensor)
		}
		if cfg.API.SensorID != "s-1" || cfg.API.BaseURL != "https://api" {
			t.Fatalf("server block: %+v", cfg.API)
		}
		if len(*warns) != 2 {
			t.Fatalf("want a warning for agent: and for server.agent_id, got %v", *warns)
		}
	})

	t.Run("new keys", func(t *testing.T) {
		warns := captureWarnings(t)
		cfg, err := load(t, "sensor:\n  name: edge-2\nserver:\n  sensor_id: s-2\n")
		if err != nil || cfg.Sensor.Name != "edge-2" || cfg.API.SensorID != "s-2" || len(*warns) != 0 {
			t.Fatalf("cfg %+v err %v warnings %v", cfg, err, *warns)
		}
	})

	t.Run("conflicting blocks are refused", func(t *testing.T) {
		captureWarnings(t)
		_, err := load(t, "agent:\n  name: a\nsensor:\n  name: b\n")
		if err == nil || !strings.Contains(err.Error(), "agent:") || !strings.Contains(err.Error(), "sensor:") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("conflicting ids are refused", func(t *testing.T) {
		captureWarnings(t)
		_, err := load(t, "server:\n  agent_id: a\n  sensor_id: b\n")
		if err == nil || !strings.Contains(err.Error(), "server.agent_id") || !strings.Contains(err.Error(), "server.sensor_id") {
			t.Fatalf("err = %v", err)
		}
	})
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
