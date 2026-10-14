package main

import (
	"os"
	"strings"
)

// The Tenable.sc connector moved out of the sensor into its own image
// (openctemio/connector-tenable): its keys no longer share a process or a
// container with scanners that parse scanned content. A sensor still set
// up for it starts without it and says so.

// connectorMovedMessage is printed when the old connector settings are found.
const connectorMovedMessage = "the Tenable.sc connector moved to ghcr.io/openctemio/connector-tenable " +
	"(https://github.com/openctemio/connector-tenable); this sensor no longer runs it. Run the connector image " +
	"with the same config file and key files, and point the Tenable.sc integration at its sensor"

// Settings the connector used while it was part of the sensor.
const (
	legacyTenableConfigEnv  = "SENSOR_TENABLE_SC_CONFIG"
	legacyTenableConfigPath = "/etc/openctem/connectors/tenable-sc.yaml"
)

// legacyTenableSettings lists the old connector settings that are set: the
// -tenable-sc-config flag, its environment variable, the TENABLE_SC_*
// shorthand, or the default config file.
func legacyTenableSettings(flagPath string, environ []string, exists func(string) bool) []string {
	var found []string
	if flagPath != "" {
		found = append(found, "-tenable-sc-config")
	}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if value == "" {
			continue
		}
		if name == legacyTenableConfigEnv || strings.HasPrefix(name, "TENABLE_SC_") {
			found = append(found, name)
		}
	}
	if exists(legacyTenableConfigPath) {
		found = append(found, legacyTenableConfigPath)
	}
	return found
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
