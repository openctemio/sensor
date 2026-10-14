package main

import (
	"slices"
	"testing"
)

func TestLegacyTenableSettings(t *testing.T) {
	none := func(string) bool { return false }
	if got := legacyTenableSettings("", []string{"PATH=/bin", "TENABLE_SC_URL="}, none); len(got) != 0 {
		t.Fatalf("nothing set: %v", got)
	}
	got := legacyTenableSettings("/etc/x.yaml", []string{"SENSOR_TENABLE_SC_CONFIG=/a", "TENABLE_SC_URL=https://sc"}, func(p string) bool { return p == legacyTenableConfigPath })
	for _, want := range []string{"-tenable-sc-config", "SENSOR_TENABLE_SC_CONFIG", "TENABLE_SC_URL", legacyTenableConfigPath} {
		if !slices.Contains(got, want) {
			t.Fatalf("%v misses %s", got, want)
		}
	}
}
