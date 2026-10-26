package main

// The data directory preflight: a daemon whose data directory its user
// cannot write (a bind mount owned by another uid is the usual cause) stops
// at once with one message that names the path, the owner, the sensor's own
// uid:gid and the fixes, instead of failing later in whichever component
// touches the directory first and crash-looping under a restart policy.

import (
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sensor/internal/content"
)

// checkDataDirs checks the outbox, state, store, workspaces and content
// directories the environment (or the image's defaults) names. Content is
// skipped when SENSOR_CONTENT=off.
func checkDataDirs(lookup func(string) (string, bool)) error {
	contentDir := ""
	if settings, err := content.SettingsFromEnv(lookup); err == nil && settings.Enabled {
		contentDir = settings.Root
	}
	return sensorkit.PreflightDataDirs(contentDir)
}

// preflightDataDirs runs checkDataDirs and exits 1 with its message.
func preflightDataDirs() {
	if err := checkDataDirs(os.LookupEnv); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
