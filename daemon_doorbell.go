package main

// Heartbeat doorbell and key renewal for the daemon (-daemon), in every build.
//
// With the doorbell the platform's heartbeat answer says when there is work
// (the sensor then polls at once instead of every 30 s), pauses or drains the
// sensor, and asks for key rotation. API: RFC-023 §9.2a; SDK: core.Doorbell.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// daemonKeyRenewer renews the daemon's API key and swaps the new key into
// every client that uses it.
type daemonKeyRenewer struct {
	renew *platform.PlatformClient // RenewKey only: POST /api/v2/sensor/keys (v1 renew on an older platform)
	api   *client.Client           // heartbeat, poll, ingest
}

func (r *daemonKeyRenewer) RenewKey(ctx context.Context) (*platform.RenewKeyResponse, error) {
	return r.renew.RenewKey(ctx)
}

func (r *daemonKeyRenewer) SetAPIKey(key string) {
	r.renew.SetAPIKey(key)
	r.api.SetAPIKey(key)
}

// loadDaemonCredentials returns the stored key for sensorID from the
// credentials file, or nil when there is none. A key renewed by an earlier
// run lives only there: the key in the config file or environment was
// revoked by that renewal.
func loadDaemonCredentials(store *platform.FileCredentialStore, sensorID string) *platform.SensorCredentials {
	if !store.Exists() {
		return nil
	}
	creds, err := store.Load()
	if err != nil || creds == nil || creds.APIKey == "" {
		return nil
	}
	if sensorID != "" && creds.SensorID != "" && creds.SensorID != sensorID {
		return nil // another sensor's file
	}
	return creds
}

// daemonKeyRenewConfig persists each rotated key, with its expiry, to the
// credentials file the next start reads.
func daemonKeyRenewConfig(store *platform.FileCredentialStore, sensorID string, expiresAt *time.Time, verbose bool) *platform.KeyRenewConfig {
	return &platform.KeyRenewConfig{
		Verbose:             verbose,
		CurrentKeyExpiresAt: expiresAt,
		OnRotated: func(newKey string, exp *time.Time) error {
			prefix := newKey
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			if err := store.Save(&platform.SensorCredentials{
				SensorID:  sensorID,
				APIKey:    newKey,
				APIPrefix: prefix,
				ExpiresAt: exp,
			}); err != nil {
				return err
			}
			fmt.Printf("[apikey] %s rotated key saved to the credentials file\n", time.Now().Format(time.RFC3339))
			return nil
		},
	}
}

// startDaemonKeyRenewal starts key auto-renewal for the daemon. The renewal
// runs on its schedule (half the key's lifetime) and at once when the
// platform's heartbeat says rotate_key.
func startDaemonKeyRenewal(ctx context.Context, cfg *Config, apiClient *client.Client, credsFile string, expiresAt *time.Time) (*platform.KeyRenewManager, error) {
	store := platform.NewFileCredentialStore(credsFile)
	renewer := &daemonKeyRenewer{
		renew: platform.NewPlatformClient(&platform.ClientConfig{
			BaseURL:  cfg.API.BaseURL,
			APIKey:   cfg.API.APIKey,
			SensorID: cfg.API.SensorID,
		}),
		api: apiClient,
	}
	m := platform.NewKeyRenewManager(renewer, daemonKeyRenewConfig(store, cfg.API.SensorID, expiresAt, cfg.Sensor.Verbose))
	if err := m.Start(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// newDaemonDoorbell builds the doorbell the heartbeat and the command poller
// share. renewNow, when non-nil, is run on rotate_key.
func newDaemonDoorbell(verbose bool, renewNow func()) *core.Doorbell {
	return core.NewDoorbell(&core.DoorbellConfig{OnRotateKey: renewNow, Verbose: verbose})
}

// resolveDaemonCredentials prepares key auto-renewal for the daemon: it picks
// the credentials file and, when it holds a key renewed by an earlier run for
// this sensor, makes that key the one the daemon starts with. Returns the
// file and the starting key's expiry (nil when unknown).
func resolveDaemonCredentials(cfg *Config, explicit string) (string, *time.Time, error) {
	file, err := platform.ResolveCredentialsFile(explicit)
	if err != nil {
		return "", nil, err
	}
	creds := loadDaemonCredentials(platform.NewFileCredentialStore(file), cfg.API.SensorID)
	if creds == nil {
		return file, nil, nil
	}
	if creds.APIKey != cfg.API.APIKey {
		fmt.Fprintf(os.Stderr, "Using the renewed API key from %s\n", file)
		cfg.API.APIKey = creds.APIKey
	}
	return file, creds.ExpiresAt, nil
}
