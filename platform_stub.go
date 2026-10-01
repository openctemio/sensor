//go:build !platform

// Platform Sensor Mode Stub - Included when NOT building with -tags platform
//
// This is the default build for public distribution.
// Build with: go build -o openctemio-sensor .
// The -platform flag will show an error message in this build.

package main

import (
	"context"
	"fmt"
	"os"
)

// platformModeEnabled indicates platform mode is NOT available in this build.
const platformModeEnabled = false

var _ = platformModeEnabled // Silence unused const warning

// PlatformSensorConfig is a stub for non-platform builds.
type PlatformSensorConfig struct {
	APIBaseURL      string
	BootstrapToken  string
	Name            string
	Region          string
	MaxConcurrent   int
	CredentialsFile string
	Verbose         bool
	Scanners        string
	Tools           string

	// Executor enable flags
	ReconEnabled    bool
	VulnScanEnabled bool
	SecretsEnabled  bool
	AssetsEnabled   bool
	PipelineEnabled bool

	// KeyAutoRenew enables sensor API-key self-renewal (platform builds only).
	KeyAutoRenew bool
}

// runPlatformSensor shows an error for non-platform builds.
func runPlatformSensor(_ context.Context, _ *PlatformSensorConfig) {
	fmt.Fprintln(os.Stderr, "Error: Platform mode is not available in this build.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "This sensor binary was built for standalone/CI use only.")
	fmt.Fprintln(os.Stderr, "Platform mode requires a special build with -tags platform.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For standalone scanning, use:")
	fmt.Fprintln(os.Stderr, "  openctemio-sensor -tool semgrep -target ./src -push")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "For more information, visit: https://github.com/openctemio/sensor")
	os.Exit(1)
}
