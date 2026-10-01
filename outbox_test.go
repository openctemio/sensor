package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clearOutboxEnv(t *testing.T) {
	for _, k := range []string{envProtocol, envOutbox, envOutboxDir, envOutboxMaxBytes, envOutboxMaxAge, envOutboxKeyFile, "RETRY_QUEUE", "RETRY_DIR"} {
		t.Setenv(k, "")
	}
}

func TestResolveProtocol(t *testing.T) {
	clearOutboxEnv(t)
	if p, err := resolveProtocol("", ""); err != nil || p != "auto" {
		t.Fatalf("default = %q, %v", p, err)
	}
	t.Setenv(envProtocol, "V1")
	if p, _ := resolveProtocol("", "v2"); p != "v1" {
		t.Fatalf("env over config = %q", p)
	}
	if p, _ := resolveProtocol("v2", ""); p != "v2" {
		t.Fatalf("flag over env = %q", p)
	}
	t.Setenv(envProtocol, "v3")
	if _, err := resolveProtocol("", ""); err == nil {
		t.Fatal("v3 accepted")
	}
}

func TestResolveOutbox_Defaults(t *testing.T) {
	clearOutboxEnv(t)
	// One-shot: off.
	p, err := resolveOutbox(OutboxSettings{}, outboxFlags{}, false)
	if err != nil || p.Enabled {
		t.Fatalf("one-shot = %+v, %v", p, err)
	}
	// Daemon: on, in an explicit dir.
	dir := t.TempDir()
	t.Setenv(envOutboxDir, dir)
	p, err = resolveOutbox(OutboxSettings{}, outboxFlags{}, true)
	if err != nil || !p.Enabled || p.Config.Dir != dir {
		t.Fatalf("daemon = %+v, %v", p, err)
	}
}

func TestResolveOutbox_FallsBackToHomeWhenDefaultIsNotWritable(t *testing.T) {
	clearOutboxEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	p, err := resolveOutbox(OutboxSettings{}, outboxFlags{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.Dir == DefaultOutboxDir {
		t.Skip("this machine can write " + DefaultOutboxDir)
	}
	if p.Config.Dir != filepath.Join(home, ".openctem", "outbox") || !strings.Contains(p.Note, DefaultOutboxDir) {
		t.Fatalf("fallback = %+v", p)
	}
}

func TestResolveOutbox_Overrides(t *testing.T) {
	clearOutboxEnv(t)
	off := false
	t.Setenv(envOutboxDir, t.TempDir())
	if p, _ := resolveOutbox(OutboxSettings{Enabled: &off}, outboxFlags{}, true); p.Enabled {
		t.Fatal("config enabled:false ignored")
	}
	// The pre-outbox opt-in turns it on for a one-shot run.
	if p, _ := resolveOutbox(OutboxSettings{}, outboxFlags{legacyQueue: true}, false); !p.Enabled {
		t.Fatal("-retry-queue ignored")
	}
	t.Setenv(envOutbox, "off")
	if p, _ := resolveOutbox(OutboxSettings{}, outboxFlags{}, true); p.Enabled {
		t.Fatal("SENSOR_OUTBOX=off ignored")
	}
	t.Setenv(envOutbox, "maybe")
	if _, err := resolveOutbox(OutboxSettings{}, outboxFlags{}, true); err == nil {
		t.Fatal("SENSOR_OUTBOX=maybe accepted")
	}
	t.Setenv(envOutbox, "on")
	t.Setenv(envOutboxMaxBytes, "512MiB")
	t.Setenv(envOutboxMaxAge, "72h")
	t.Setenv("RETRY_DIR", "/old/queue")
	p, err := resolveOutbox(OutboxSettings{}, outboxFlags{}, false)
	if err != nil || p.Config.MaxBytes != 512<<20 || p.Config.MaxAge != 72*time.Hour || p.Config.LegacyRetryQueueDir != "/old/queue" {
		t.Fatalf("overrides = %+v, %v", p.Config, err)
	}
	t.Setenv(envOutboxMaxAge, "-1h")
	if _, err := resolveOutbox(OutboxSettings{}, outboxFlags{}, true); err == nil {
		t.Fatal("negative max age accepted")
	}
}

func TestParseByteSize(t *testing.T) {
	cases := map[string]int64{"": 0, "1GiB": 1 << 30, "512MiB": 512 << 20, "100MB": 100_000_000, "2g": 2 << 30, "1048576": 1 << 20, "1.5GiB": 3 << 29}
	for in, want := range cases {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"lots", "-1GiB", "0"} {
		if _, err := parseByteSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
