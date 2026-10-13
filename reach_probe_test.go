package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sensor/internal/reachprobe"
)

// probePolicy allows one documentation range; everything else is refused.
const probePolicy = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow:
    - 198.51.100.0/24
`

// refusingDial records each address and answers "connection refused" (the
// path works, the port is closed): no packet leaves the test.
type refusingDial struct {
	mu     sync.Mutex
	dialed []string
}

func (d *refusingDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func (d *refusingDial) addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// startProbeSensor starts a daemon kit that runs commands, with the reach
// probe added as runDaemon adds it, against p.
func startProbeSensor(t *testing.T, p conformance.SensorEndpoint, d *refusingDial) func() {
	t.Helper()
	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pp, []byte(probePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	lp, err := core.LoadLocalPolicy(core.LocalPolicyOptions{Path: pp})
	if err != nil {
		t.Fatal(err)
	}
	kit, err := sensorkit.New(sensorkit.Options{
		Name: "probe-test", Version: Version, APIURL: p.URL, APIKey: p.APIKey,
		StateDir: filepath.Join(dir, "state"), Outbox: sensorkit.OutboxSettings{Dir: filepath.Join(dir, "outbox")},
		LocalPolicy: lp, Settings: sensorSettings(), CommandPollInterval: 100 * time.Millisecond,
		HeartbeatInterval: 200 * time.Millisecond, Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	addReachProbe(kit, d.dial)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- kit.Run(ctx) }()
	return func() { cancel(); <-done }
}

func probePayload(targets ...string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"scanner": reachprobe.Name, "targets": targets})
	return b
}

// The sensor with the probe keeps the platform contract (the SDK's sensor
// conformance suite), running a probe job to completion.
func TestReachProbe_SensorConformance(t *testing.T) {
	httpsec.AllowLoopback = true
	t.Cleanup(func() { httpsec.AllowLoopback = false })
	d := &refusingDial{}
	conformance.RunSensorSuite(t, func(t *testing.T, p conformance.SensorEndpoint) func() {
		return startProbeSensor(t, p, d)
	}, conformance.SuiteOptions{ScanPayload: probePayload("198.51.100.7"), Timeout: 30 * time.Second})
}

// A probe job runs on the platform's request: the sensor advertises the
// capability, the result carries the reach summary, and an address outside
// the local policy is never dialed.
func TestReachProbe_Job(t *testing.T) {
	httpsec.AllowLoopback = true
	t.Cleanup(func() { httpsec.AllowLoopback = false })
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetManifest(true)
	t.Cleanup(f.Close)
	const id = "0192a3b4-0000-7000-8000-0000000000a1"
	f.QueueCommandPayload(id, "scan", probePayload("198.51.100.7", "203.0.113.5"))
	d := &refusingDial{}
	stop := startProbeSensor(t, conformance.SensorEndpoint{URL: f.URL(), APIKey: f.APIKey}, d)
	t.Cleanup(stop)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := f.CommandState(id); s == "completed" || s == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s, e := f.CommandState(id); s != "completed" {
		t.Fatalf("probe command ended %q (%s), want completed", s, e)
	}
	res := string(f.CommandResult(id))
	if !strings.Contains(res, `"reach"`) || !strings.Contains(res, `"port_closed"`) {
		t.Fatalf("the result carries no reach summary: %s", res)
	}
	for _, a := range d.addrs() {
		if !strings.HasPrefix(a, "198.51.100.7:") {
			t.Fatalf("SECURITY: dialed %s, outside the local policy", a)
		}
	}
	if len(d.addrs()) == 0 {
		t.Fatal("the admitted target was not probed")
	}
	advertised := false
	for _, hb := range f.Heartbeats() {
		if strings.Contains(string(hb), reachprobe.Capability) {
			advertised = true
		}
	}
	if !advertised {
		t.Fatalf("no heartbeat advertises %s", reachprobe.Capability)
	}
}
