package main

import (
	"slices"
	"testing"
)

// The files that hold the sensor's API key or a connector's keys are
// protected from every tool run.
func TestProtectedConfigPaths(t *testing.T) {
	t.Setenv(legacyTenableConfigEnv, "/run/secrets/tenable.yaml")
	got := protectedConfigPaths(daemonOptions{configPath: "/etc/openctem/sensor.yaml", tenableSCConfig: "/etc/x/tsc.yaml"})
	for _, want := range []string{"/etc/openctem/sensor.yaml", "/etc/x/tsc.yaml", "/run/secrets/tenable.yaml", legacyTenableConfigPath} {
		if !slices.Contains(got, want) {
			t.Errorf("%s not protected: %v", want, got)
		}
	}
}

// A one-shot run is not sandboxed unless asked, and an unknown mode is an
// error rather than silently off.
func TestOneShotSandboxMode(t *testing.T) {
	t.Setenv("SENSOR_SANDBOX", "")
	if err := oneShotSandbox("", ""); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENSOR_SANDBOX", "loose")
	if err := oneShotSandbox("", ""); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
