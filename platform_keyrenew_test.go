//go:build platform

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/platform"
)

// A rotation must persist the new key's expiry, and the next start must seed
// the renewer from it. Before, the expiry was dropped, so every restart looked
// like an unknown key and the renewer rotated a still-valid key immediately.
func TestKeyRenewConfig_ExpirySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-credentials.json")
	store := platform.NewFileCredentialStore(path)

	var ingestKey string
	cfg := keyRenewConfig(&platform.SensorCredentials{SensorID: "agent-1", APIKey: "oct_old"},
		store, func(k string) { ingestKey = k }, false)
	if cfg.CurrentKeyExpiresAt != nil {
		t.Fatalf("no stored expiry yet, got %v", cfg.CurrentKeyExpiresAt)
	}

	exp := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	if err := cfg.OnRotated("oct_newkey_0123456789", &exp); err != nil {
		t.Fatalf("OnRotated: %v", err)
	}
	if ingestKey != "oct_newkey_0123456789" {
		t.Fatalf("ingest client not rotated, got %q", ingestKey)
	}

	// Restart: credentials come back through the same path the agent uses.
	creds, err := platform.EnsureRegistered(context.Background(), &platform.EnsureRegisteredConfig{
		BaseURL:         "https://api.example.com",
		CredentialsFile: path,
	})
	if err != nil {
		t.Fatalf("EnsureRegistered: %v", err)
	}
	if creds.APIKey != "oct_newkey_0123456789" || creds.SensorID != "agent-1" {
		t.Fatalf("reloaded creds = %+v", creds)
	}
	if creds.ExpiresAt == nil || !creds.ExpiresAt.Equal(exp) {
		t.Fatalf("reloaded expiry = %v, want %v", creds.ExpiresAt, exp)
	}

	next := keyRenewConfig(creds, store, func(string) {}, false)
	if next.CurrentKeyExpiresAt == nil || !next.CurrentKeyExpiresAt.Equal(exp) {
		t.Fatalf("renewer not seeded from stored expiry: %v", next.CurrentKeyExpiresAt)
	}
}
