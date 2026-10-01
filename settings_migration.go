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
// API_URL, API_KEY and BOOTSTRAP_TOKEN were never renamed. The credentials
// file (~/.openctem/agent-credentials.json) is moved by the SDK
// (platform.ResolveCredentialsFile).

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
	"gopkg.in/yaml.v3"
)

// renamedEnv are the binary's renamed environment variables.
var renamedEnv = []legacyv1.RenamedVar{
	{Old: "AGENT_ID", New: "SENSOR_ID"},
	{Old: "AGENT_NAME", New: "SENSOR_NAME"},
	{Old: "AGENT_ALLOW_PRIVATE_TARGETS", New: "SENSOR_ALLOW_PRIVATE_TARGETS"},
}

// renamedFlags are the binary's renamed command-line flags.
var renamedFlags = []legacyv1.RenamedVar{
	{Old: "agent-id", New: "sensor-id"},
}

// migrateEnv applies every renamed environment variable that is set only
// under its old name to its new name, so the rest of the binary (and the
// SDK) reads only new names. It returns an error naming both variables when
// they are set to different values.
func migrateEnv(lookup func(string) (string, bool), setenv func(string, string) error) error {
	var errs []error
	for _, r := range renamedEnv {
		v, ok, err := legacyv1.Resolve(r.New, r.Old, "environment", lookup)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, hasNew := lookup(r.New); ok && !hasNew {
			if err := setenv(r.New, v); err != nil {
				errs = append(errs, fmt.Errorf("apply %s from deprecated %s: %w", r.New, r.Old, err))
			}
		}
	}
	return errors.Join(errs...)
}

// migrateFlags does the same for flags given on the command line: an old
// flag's value is applied to its replacement, with a warning.
func migrateFlags(fs *flag.FlagSet) error {
	given := map[string]string{}
	fs.Visit(func(f *flag.Flag) { given["-"+f.Name] = f.Value.String() })
	lookup := func(name string) (string, bool) { v, ok := given[name]; return v, ok }

	var errs []error
	for _, r := range renamedFlags {
		v, ok, err := legacyv1.Resolve("-"+r.New, "-"+r.Old, "flag", lookup)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, hasNew := given["-"+r.New]; ok && !hasNew {
			if err := fs.Set(r.New, v); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

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

// migrateSettings runs the environment and flag migrations at startup and
// exits, naming the settings, when old and new names conflict.
func migrateSettings(fs *flag.FlagSet) {
	err := errors.Join(migrateEnv(os.LookupEnv, os.Setenv), migrateFlags(fs))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
