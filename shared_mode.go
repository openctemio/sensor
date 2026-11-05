package main

import (
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"

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

// inProcessUnconfined refuses the in-process tool runtime (SENSOR_TOOL_RUNTIME=
// in-process) on a host whose tool sandbox is not available: the tool host
// refuses tools that contact their targets there (they would run
// unconfined), and the in-process runtime would run them without that check.
// SENSOR_SANDBOX=off is the operator's acknowledgement for both.
func inProcessUnconfined(st executor.Status) error {
	if toolrun.OutOfProcess() || !st.RefusesActiveTools() {
		return nil
	}
	return fmt.Errorf("%s=in-process runs tools without the tool host's checks, and this host has no tool sandbox (it is Linux only), "+
		"so tools that contact their targets would run unconfined; unset %s, or set %s=off to acknowledge running tools unconfined",
		toolrun.EnvRuntime, toolrun.EnvRuntime, sensorkit.EnvSandbox)
}
