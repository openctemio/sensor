package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// A key the daemon renewed is saved with its expiry, and the next start uses
// it instead of the configured (now revoked) key.
func TestDaemonKeyRenewal_PersistsAndIsReloaded(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sensor-credentials.json")
	store := platform.NewFileCredentialStore(file)
	exp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

	rc := daemonKeyRenewConfig(store, "sensor-1", nil, false)
	if err := rc.OnRotated("oct_newkey_123456", &exp); err != nil {
		t.Fatal(err)
	}

	var cfg Config
	cfg.API.APIKey = "oct_configured"
	cfg.API.SensorID = "sensor-1"
	gotFile, gotExp, err := resolveDaemonCredentials(&cfg, file)
	if err != nil {
		t.Fatal(err)
	}
	if gotFile != file || cfg.API.APIKey != "oct_newkey_123456" {
		t.Fatalf("file %q key %q", gotFile, cfg.API.APIKey)
	}
	if gotExp == nil || !gotExp.Equal(exp) {
		t.Fatalf("expiry %v, want %v", gotExp, exp)
	}

	// Another sensor's file is not used.
	var other Config
	other.API.APIKey = "oct_other"
	other.API.SensorID = "sensor-2"
	if _, exp2, err := resolveDaemonCredentials(&other, file); err != nil || exp2 != nil || other.API.APIKey != "oct_other" {
		t.Fatalf("another sensor's credentials were used: key %q exp %v err %v", other.API.APIKey, exp2, err)
	}
}

func TestDaemonKeyRenewer_SwapsEveryClient(t *testing.T) {
	api := client.New(&client.Config{BaseURL: "https://api.example", APIKey: "old"})
	r := &daemonKeyRenewer{
		renew: platform.NewPlatformClient(&platform.ClientConfig{BaseURL: "https://api.example", APIKey: "old"}),
		api:   api,
	}
	var _ platform.KeyRenewer = r
	r.SetAPIKey("new") // must not panic; both clients take the key
}

func TestNewDaemonDoorbell(t *testing.T) {
	called := make(chan struct{}, 1)
	d := newDaemonDoorbell(false, func() { called <- struct{}{} })
	d.Handle(&core.HeartbeatHints{Present: true, Actions: []core.HeartbeatAction{core.HeartbeatActionPause, core.HeartbeatActionRotateKey}})
	if d.State() != "paused by platform" {
		t.Fatalf("state %q", d.State())
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("rotate_key did not reach the key renewal")
	}
}
