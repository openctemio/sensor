package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

func captureWarnings(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := legacyv1.Warn
	legacyv1.Warn = func(old, replacement, kind string) { got = append(got, kind+": "+old+" -> "+replacement) }
	t.Cleanup(func() { legacyv1.Warn = prev })
	return &got
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
