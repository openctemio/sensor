package main

// Settings from before the agent -> sensor rename (RFC-023 §9.5, "Upgrade
// migration for existing installations"). Installations set them in .env
// files, systemd units, compose files, Helm values and CI pipelines, so an
// upgraded sensor must keep working with them unchanged:
//
//   - the new name is read first;
//   - an old name is applied to the new one, with a startup warning naming
//     both;
//   - startup is refused only when an old and a new name are both set to
//     different values (silently picking one could, for example, switch
//     private-network scanning on or off).
//
// The SDK migrates the environment (AGENT_ID, AGENT_NAME,
// AGENT_ALLOW_PRIVATE_TARGETS) and the -agent-id flag
// (sensorkit.MigrateSettings) and moves the credentials file
// (~/.openctem/agent-credentials.json, platform.ResolveCredentialsFile); this
// file migrates the sensor's own configuration file. API_URL, API_KEY and
// BOOTSTRAP_TOKEN were never renamed.

import (
	"fmt"
	"reflect"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
	"gopkg.in/yaml.v3"
)

// migrateConfigFile applies the pre-rename keys of a -config file: the
// top-level `agent:` block is now `sensor:` and `server.agent_id` is now
// `server.sensor_id`. data is the file after environment expansion; cfg has
// already been decoded from it with the new keys.
func migrateConfigFile(data []byte, cfg *Config) error {
	var keys struct {
		// yaml.v3 fills a yaml.Node value (not a pointer); Kind is zero when
		// the key is absent.
		Sensor      yaml.Node `yaml:"sensor"`
		LegacyBlock yaml.Node `yaml:"agent"`
		Server      struct {
			SensorID       *string `yaml:"sensor_id"`
			LegacySensorID *string `yaml:"agent_id"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if keys.LegacyBlock.Kind != 0 {
		var old SensorSettings
		if err := keys.LegacyBlock.Decode(&old); err != nil {
			return fmt.Errorf("parse config: agent: %w", err)
		}
		if keys.Sensor.Kind != 0 && !reflect.DeepEqual(old, cfg.Sensor) {
			return &legacyv1.ConflictError{Old: "agent: block", New: "sensor: block"}
		}
		legacyv1.Deprecated("agent:", "sensor:", "configuration key")
		cfg.Sensor = old
	}

	given := map[string]string{}
	if keys.Server.SensorID != nil {
		given["server.sensor_id"] = *keys.Server.SensorID
	}
	if keys.Server.LegacySensorID != nil {
		given["server.agent_id"] = *keys.Server.LegacySensorID
	}
	id, ok, err := legacyv1.Resolve("server.sensor_id", "server.agent_id", "configuration key",
		func(k string) (string, bool) { v, ok := given[k]; return v, ok })
	if err != nil {
		return err
	}
	if ok {
		cfg.API.SensorID = id
	}
	return nil
}
