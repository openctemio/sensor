package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"

	"github.com/openctemio/sensor/internal/toolrun"
)

// Shared mode comes from -shared or SENSOR_SHARED_MODE=1; a typo in the
// switch is an error, never a sensor without isolation.
func TestSharedModeSwitch(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	for _, tc := range []struct {
		flag    bool
		env     string
		want    bool
		wantErr bool
	}{
		{false, "", false, false},
		{true, "", true, false},
		{false, "1", true, false},
		{false, "0", false, false},
		{false, "yes", false, true},
	} {
		t.Setenv(sensorkit.EnvSharedMode, tc.env)
		got, err := sharedMode(tc.flag)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("flag %v env %q: got %v, %v", tc.flag, tc.env, got, err)
		}
	}
}

// SECURITY: a shared sensor never runs tools in its own process, outside
// the task sandbox.
func TestSharedModeRefusesInProcessTools(t *testing.T) {
	t.Setenv(sensorkit.EnvSharedMode, "")
	t.Setenv(toolrun.EnvRuntime, "in-process")
	if _, err := sharedMode(true); err == nil || !strings.Contains(err.Error(), toolrun.EnvRuntime) {
		t.Fatalf("in-process tools accepted in shared mode: %v", err)
	}
	if shared, err := sharedMode(false); err != nil || shared {
		t.Fatalf("not shared: %v %v", shared, err)
	}
}

// SECURITY (DNS rebinding): the daemon's tool admission policy gives the
// tool host the addresses the local policy checked, so a name re-bound to
// an internal address after admission is never pinned for a task.
func TestKitPolicyAdmittedAddrsAreChecked(t *testing.T) {
	t.Setenv(core.EnvSensorAllowPrivateTargets, "")
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [rebind.example.com]}\n"),
		core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }, LookupIP: resolveTo("10.0.0.5")})
	if err != nil {
		t.Fatal(err)
	}
	p := kitPolicy{current: func() *core.LocalPolicy { return lp }}
	if got, err := p.AdmittedAddrs(context.Background(), "rebind.example.com"); err == nil {
		t.Fatalf("a name resolving to 10.0.0.5 was admitted at %v", got)
	}
}

func resolveTo(addr string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(addr)}, nil }
}
