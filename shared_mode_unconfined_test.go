package main

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sensor/internal/toolrun"
)

// SECURITY: on a host without the tool sandbox, the in-process runtime
// (which skips the tool host's refusal of unconfined active tools) does not
// start unless the operator turned the sandbox off.
func TestInProcessRuntimeRefusedWithoutSandbox(t *testing.T) {
	unavailable := executor.Status{Mode: executor.ModeAuto}
	off := executor.Status{Mode: executor.ModeOff}
	sandboxed := executor.Status{Mode: executor.ModeAuto, Sandboxed: true}

	t.Setenv(toolrun.EnvRuntime, "in-process")
	if err := inProcessUnconfined(unavailable); err == nil || !strings.Contains(err.Error(), "SENSOR_SANDBOX=off") {
		t.Fatalf("in-process without a sandbox: %v", err)
	}
	if err := inProcessUnconfined(off); err != nil {
		t.Fatalf("acknowledged: %v", err)
	}
	if err := inProcessUnconfined(sandboxed); err != nil {
		t.Fatalf("sandboxed: %v", err)
	}
	t.Setenv(toolrun.EnvRuntime, "")
	if err := inProcessUnconfined(unavailable); err != nil {
		t.Fatalf("out of process (the tool host refuses per tool): %v", err)
	}
}
