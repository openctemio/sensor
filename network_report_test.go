package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/netctx"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

// networkPolicy allows one private range: the network report may name
// nothing outside it.
const networkPolicy = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow:
    - 10.20.0.0/16
  allow_private: true
`

// runNetworkSensor runs a daemon kit (the sensor's settings and a local
// policy, as runDaemon builds it) against a fake platform that reads
// network reports, and returns the first manifest's network member.
func runNetworkSensor(t *testing.T) *netctx.Report {
	t.Helper()
	httpsec.AllowLoopback = true
	t.Cleanup(func() { httpsec.AllowLoopback = false })
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetManifest(true)
	f.SetNetwork(true)
	t.Cleanup(f.Close)

	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pp, []byte(networkPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	lp, err := core.LoadLocalPolicy(core.LocalPolicyOptions{Path: pp})
	if err != nil {
		t.Fatal(err)
	}
	kit, err := sensorkit.New(sensorkit.Options{
		Name: "network-test", Version: Version, APIURL: f.URL(), APIKey: f.APIKey,
		StateDir: filepath.Join(dir, "state"), Outbox: sensorkit.OutboxSettings{Dir: filepath.Join(dir, "outbox")},
		DisableCommands: true, LocalPolicy: lp, Settings: sensorSettings(), ReportUnknownEnv: true,
		HeartbeatInterval: 200 * time.Millisecond, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- kit.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, raw := range f.Manifests() {
			var m struct {
				Network *netctx.Report `json:"network"`
			}
			if json.Unmarshal(raw, &m) == nil && m.Network != nil {
				return m.Network
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no manifest carried a network report")
	return nil
}

// The manifest carries the network report: the host owner's declaration
// from SENSOR_NETWORK_*, never wider than the local policy (the declared
// range outside targets.allow is left out), summary by default.
func TestNetworkReport_DeclaredNarrowedByPolicy(t *testing.T) {
	t.Setenv("SENSOR_ALLOW_PRIVATE_TARGETS", "1")
	t.Setenv(netctx.EnvSite, "hn-01")
	t.Setenv(netctx.EnvReach, "10.20.0.0/16,172.16.0.0/12")
	t.Setenv(netctx.EnvDNSSuffixes, "corp.example.com")
	t.Setenv(netctx.EnvInternet, "none")
	r := runNetworkSensor(t)
	if r.Mode != netctx.ModeSummary || !strings.HasPrefix(r.Fingerprint, "sha256:") {
		t.Fatalf("report mode %q fingerprint %q", r.Mode, r.Fingerprint)
	}
	if r.Internet != netctx.InternetNone || !r.InternetDeclared {
		t.Fatalf("internet %q (declared %v), want none as declared", r.Internet, r.InternetDeclared)
	}
	if r.Declared == nil || r.Declared.Site != "hn-01" || !slices.Equal(r.Declared.DNSSuffixes, []string{"corp.example.com"}) {
		t.Fatalf("declared = %+v", r.Declared)
	}
	if !slices.Equal(r.Declared.Reach, []string{"10.20.0.0/16"}) || r.Trimmed < 1 {
		t.Fatalf("SECURITY: declared reach %v (trimmed %d), want only the policy's 10.20.0.0/16", r.Declared.Reach, r.Trimmed)
	}
	if r.Detected != nil {
		for _, p := range r.Detected.OnLink {
			if !strings.HasPrefix(p, "10.20.") {
				t.Errorf("SECURITY: on-link prefix %s outside the local policy reported", p)
			}
		}
	}
}

// A sensor that may not scan private targets (allow_private in the policy
// without SENSOR_ALLOW_PRIVATE_TARGETS) names no private prefix at all.
func TestNetworkReport_NoPrivateTargetsNoPrivatePrefixes(t *testing.T) {
	t.Setenv("SENSOR_ALLOW_PRIVATE_TARGETS", "")
	t.Setenv(netctx.EnvSite, "hn-01")
	t.Setenv(netctx.EnvReach, "10.20.0.0/16")
	r := runNetworkSensor(t)
	if r.Declared == nil || r.Declared.Site != "hn-01" {
		t.Fatalf("declared = %+v", r.Declared)
	}
	if len(r.Declared.Reach) != 0 || r.Trimmed < 1 {
		t.Fatalf("SECURITY: private reach %v reported by a sensor that may not scan private targets", r.Declared.Reach)
	}
	if r.Detected != nil && len(r.Detected.OnLink) != 0 {
		t.Fatalf("SECURITY: private on-link prefixes %v reported", r.Detected.OnLink)
	}
}

// SENSOR_NETWORK_REPORT=off: only the fingerprint and the internet mode.
func TestNetworkReport_Off(t *testing.T) {
	t.Setenv(netctx.EnvSite, "hn-01")
	t.Setenv(netctx.EnvReach, "10.20.0.0/16")
	t.Setenv(netctx.EnvReport, "off")
	r := runNetworkSensor(t)
	if r.Mode != netctx.ModeOff || r.Declared != nil || r.Detected != nil || r.EgressAddress != "" {
		t.Fatalf("off report says more than the fingerprint and internet mode: %+v", r)
	}
}

// A declaration the sensor cannot use stops it: it never runs with a
// network report the host owner did not mean.
func TestNetworkReport_InvalidDeclarationStops(t *testing.T) {
	for env, v := range map[string]string{
		netctx.EnvInternet: "sometimes",
		netctx.EnvReach:    "not-a-cidr",
		netctx.EnvReport:   "everything",
	} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, v)
			_, err := sensorkit.New(sensorkit.Options{Name: "t", Standalone: true, DisableCommands: true,
				StateDir: t.TempDir(), Settings: sensorSettings(), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
			if err == nil {
				t.Fatalf("%s=%s accepted", env, v)
			}
		})
	}
}
