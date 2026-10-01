//go:build platform

package main

import "testing"

func hasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// buildCapabilities must ALWAYS advertise "validate": the daemon unconditionally
// wraps the command executor with a safe-check validate handler, so without this
// the API's availability gate refuses to dispatch and live validation is dormant.
func TestBuildCapabilities_AlwaysAdvertisesValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  *PlatformSensorConfig
	}{
		{"no executors enabled", &PlatformSensorConfig{}},
		{"recon only", &PlatformSensorConfig{ReconEnabled: true}},
		{"secrets only", &PlatformSensorConfig{SecretsEnabled: true}},
		{"vulnscan only", &PlatformSensorConfig{VulnScanEnabled: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasCapability(buildCapabilities(tc.cfg), "validate") {
				t.Fatalf("expected 'validate' to always be advertised, caps=%v", buildCapabilities(tc.cfg))
			}
		})
	}
}

// validate:nuclei rides the vuln-scan (nuclei) image — advertised iff VulnScan is on.
func TestBuildCapabilities_NucleiGatedOnVulnScan(t *testing.T) {
	with := buildCapabilities(&PlatformSensorConfig{VulnScanEnabled: true})
	if !hasCapability(with, "validate:nuclei") {
		t.Fatalf("expected 'validate:nuclei' when VulnScanEnabled, caps=%v", with)
	}
	without := buildCapabilities(&PlatformSensorConfig{VulnScanEnabled: false})
	if hasCapability(without, "validate:nuclei") {
		t.Fatalf("did not expect 'validate:nuclei' without VulnScan, caps=%v", without)
	}
}
