package main

import (
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/sensorkit"

	"github.com/openctemio/sensor/internal/toolrun"
)

// sharedMode decides whether the daemon runs in shared mode (-shared, else
// SENSOR_SHARED_MODE=1), the SDK's per-job isolation profile for a sensor
// that runs jobs of many tenants (api RFC-100 §8 in openctemio/openctem).
// The SDK enforces the profile; the sensor only refuses what it alone
// knows: tools that run in the sensor's own process (SENSOR_TOOL_RUNTIME=
// in-process) are outside the task sandbox, so a shared sensor never runs
// them.
func sharedMode(flagSet bool) (bool, error) {
	env, err := sensorkit.SharedModeFromEnv()
	if err != nil {
		return false, err
	}
	shared := flagSet || env
	if shared && !toolrun.OutOfProcess() {
		return false, fmt.Errorf("shared mode runs every tool out of process, in its sandbox; unset %s (it is %q)", toolrun.EnvRuntime, os.Getenv(toolrun.EnvRuntime))
	}
	return shared, nil
}
