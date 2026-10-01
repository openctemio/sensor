package main

// Results delivery: the protocol (SENSOR_PROTOCOL) and the durable outbox
// (SENSOR_OUTBOX_*). The SDK does the work (sdk-go pkg/outbox and the
// protocol v2 client, api RFC-026); this file turns the sensor's flags,
// environment and config file into its settings.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/outbox"
)

// DefaultOutboxDir is where a daemon keeps undelivered results. The images
// declare it as a VOLUME; mount a persistent volume there.
const DefaultOutboxDir = "/var/lib/openctem/outbox"

// Environment variables of results delivery.
const (
	envProtocol       = "SENSOR_PROTOCOL"         // auto (default) | v1 | v2
	envOutbox         = "SENSOR_OUTBOX"           // on | off (default: on for -daemon)
	envOutboxDir      = "SENSOR_OUTBOX_DIR"       // default /var/lib/openctem/outbox
	envOutboxMaxBytes = "SENSOR_OUTBOX_MAX_BYTES" // e.g. 512MiB, 2GiB (default 1GiB)
	envOutboxMaxAge   = "SENSOR_OUTBOX_MAX_AGE"   // e.g. 72h (default 168h)
	envOutboxKeyFile  = "SENSOR_OUTBOX_KEY_FILE"  // default <dir>/outbox.key
)

// OutboxSettings is the outbox: block of the configuration file.
type OutboxSettings struct {
	// Enabled: default on in daemon mode, off for a one-shot run.
	Enabled *bool `yaml:"enabled"`
	// Dir: default /var/lib/openctem/outbox, else ~/.openctem/outbox when
	// that is not writable.
	Dir string `yaml:"dir"`
	// KeyFile is the encryption key (default <dir>/outbox.key). Point it at
	// a mounted secret to keep the key off the data volume.
	KeyFile string `yaml:"key_file"`
	// MaxBytes caps the disk use ("1GiB", "512MiB" or bytes).
	MaxBytes string `yaml:"max_bytes"`
	// MaxAge drops results older than this (default 168h).
	MaxAge time.Duration `yaml:"max_age"`
}

// outboxFlags are the command-line settings of results delivery.
type outboxFlags struct {
	protocol    string
	dir         string
	status      bool
	requeueDead bool
	// legacy retry queue (-retry-queue / -retry-dir, RETRY_QUEUE / RETRY_DIR)
	legacyQueue bool
	legacyDir   string
}

// resolveProtocol returns the results protocol: flag, SENSOR_PROTOCOL, config.
func resolveProtocol(flagVal, configured string) (string, error) {
	v := firstNonEmpty(flagVal, os.Getenv(envProtocol), configured)
	p, err := client.ParseProtocol(v)
	if err != nil {
		return "", fmt.Errorf("%s: %w", envProtocol, err)
	}
	return p, nil
}

// outboxPlan is what resolveOutbox decided.
type outboxPlan struct {
	Enabled bool
	Config  client.OutboxConfig
	// Note explains a fall-back the operator should know about.
	Note string
}

// resolveOutbox decides whether and where the outbox runs.
func resolveOutbox(s OutboxSettings, f outboxFlags, daemon bool) (outboxPlan, error) {
	var p outboxPlan
	enabled := daemon
	if s.Enabled != nil {
		enabled = *s.Enabled
	}
	if f.legacyQueue || strings.EqualFold(os.Getenv("RETRY_QUEUE"), "true") {
		enabled = true // the pre-outbox opt-in still works
	}
	if v := strings.TrimSpace(os.Getenv(envOutbox)); v != "" {
		on, err := parseOnOff(v)
		if err != nil {
			return p, fmt.Errorf("%s: %w", envOutbox, err)
		}
		enabled = on
	}
	p.Enabled = enabled

	maxBytes, err := parseByteSize(firstNonEmpty(os.Getenv(envOutboxMaxBytes), s.MaxBytes))
	if err != nil {
		return p, fmt.Errorf("%s: %w", envOutboxMaxBytes, err)
	}
	maxAge := s.MaxAge
	if v := strings.TrimSpace(os.Getenv(envOutboxMaxAge)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return p, fmt.Errorf("%s: %q is not a positive duration (e.g. 72h)", envOutboxMaxAge, v)
		}
		maxAge = d
	}
	p.Config = client.OutboxConfig{
		KeyFile:             firstNonEmpty(os.Getenv(envOutboxKeyFile), s.KeyFile),
		MaxBytes:            maxBytes,
		MaxAge:              maxAge,
		LegacyRetryQueueDir: firstNonEmpty(f.legacyDir, os.Getenv("RETRY_DIR")),
	}
	if !enabled {
		return p, nil
	}

	explicit := firstNonEmpty(f.dir, os.Getenv(envOutboxDir), s.Dir)
	if explicit != "" {
		p.Config.Dir = explicit
		return p, nil
	}
	if err := usableDir(DefaultOutboxDir); err == nil {
		p.Config.Dir = DefaultOutboxDir
		return p, nil
	} else if home, herr := os.UserHomeDir(); herr == nil {
		p.Config.Dir = filepath.Join(home, ".openctem", "outbox")
		p.Note = fmt.Sprintf("%s is not usable (%v); undelivered results are kept in %s instead. In a container, mount a volume at %s (or set %s)",
			DefaultOutboxDir, err, p.Config.Dir, DefaultOutboxDir, envOutboxDir)
		return p, nil
	} else {
		return p, fmt.Errorf("no outbox directory: %s is not usable (%v) and there is no home directory; set %s", DefaultOutboxDir, err, envOutboxDir)
	}
}

// usableDir creates dir (0700) if needed and checks a file can be written.
func usableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func parseOnOff(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes", "enabled":
		return true, nil
	case "0", "off", "false", "no", "disabled":
		return false, nil
	}
	return false, fmt.Errorf("%q is not on or off", v)
}

// parseByteSize reads "1GiB", "512MiB", "100MB", "1048576" (0 for "").
func parseByteSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		mult   int64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40},
		{"kb", 1000}, {"mb", 1000 * 1000}, {"gb", 1000 * 1000 * 1000}, {"tb", 1000 * 1000 * 1000 * 1000},
		{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"t", 1 << 40}, {"b", 1},
	}
	lower := strings.ToLower(v)
	mult := int64(1)
	num := lower
	for _, u := range units {
		if strings.HasSuffix(lower, u.suffix) {
			mult, num = u.mult, strings.TrimSpace(strings.TrimSuffix(lower, u.suffix))
			break
		}
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a size (e.g. 1GiB, 512MiB)", v)
	}
	return int64(n * float64(mult)), nil
}

// enableOutbox opens the outbox on the client and logs where it is.
func enableOutbox(c *client.Client, p outboxPlan, verbose bool) error {
	if !p.Enabled {
		return nil
	}
	if p.Note != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", p.Note)
	}
	cfg := p.Config
	if err := c.EnableOutbox(cfg); err != nil {
		if errors.Is(err, outbox.ErrLocked) {
			return fmt.Errorf("%w: another sensor process uses this outbox directory; give each sensor its own volume", err)
		}
		return err
	}
	st, _ := c.OutboxStats()
	fmt.Printf("  Outbox: %s (%d pending, %d dead letters)\n", cfg.Dir, st.PendingCount, st.DeadLetterCount)
	if verbose && st.PendingCount > 0 {
		fmt.Printf("  Outbox: delivering %d result(s) left by an earlier run\n", st.PendingCount)
	}
	return nil
}

// flushOutbox delivers what it can before a one-shot run exits and says what
// is left.
func flushOutbox(c *client.Client, timeout time.Duration) {
	st, ok := c.OutboxStats()
	if !ok {
		return
	}
	if st.PendingCount > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = c.FlushOutbox(ctx)
		cancel()
		st, _ = c.OutboxStats()
	}
	if st.PendingCount > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d result(s) could not be delivered yet; they stay in the outbox (%s) and the next run delivers them\n",
			st.PendingCount, c.Outbox().Dir())
	}
	if st.DeadLetterCount > 0 {
		fmt.Fprintf(os.Stderr, "Warning: the platform refused %d result(s); see %s\n", st.DeadLetterCount, filepath.Join(c.Outbox().Dir(), "dead"))
	}
}

// runOutboxCommand serves -outbox-status and -outbox-requeue-dead, which read
// the outbox without contacting the platform.
func runOutboxCommand(p outboxPlan, f outboxFlags) int {
	if p.Config.Dir == "" {
		fmt.Fprintln(os.Stderr, "Error: the outbox is off; set SENSOR_OUTBOX=on or SENSOR_OUTBOX_DIR")
		return 1
	}
	ob, err := outbox.Open(outbox.Config{Dir: p.Config.Dir, KeyFile: p.Config.KeyFile, MaxBytes: p.Config.MaxBytes, MaxAge: p.Config.MaxAge})
	if errors.Is(err, outbox.ErrLocked) {
		fmt.Fprintf(os.Stderr, "Error: %v.\nA running sensor holds the outbox: stop it first, or read its outbox state on the platform (the sensor's heartbeat reports it).\n", err)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer func() { _ = ob.Close() }()
	if f.requeueDead {
		n := 0
		for _, d := range ob.DeadLetters() {
			if err := ob.RequeueDead(d.Meta.ID); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s: %v\n", d.Meta.ID, err)
				continue
			}
			n++
		}
		fmt.Printf("Requeued %d dead letter(s); the daemon delivers them on its next attempt.\n", n)
	}
	st := ob.Stats()
	fmt.Printf("Outbox %s\n", ob.Dir())
	fmt.Printf("  pending:      %d (%d bytes), oldest %s\n", st.PendingCount, st.PendingBytes, st.OldestAge(time.Now()).Round(time.Second))
	fmt.Printf("  dead letters: %d (%d bytes)\n", st.DeadLetterCount, st.DeadLetterBytes)
	fmt.Printf("  byte cap:     %d\n", st.CapBytes)
	for _, d := range ob.DeadLetters() {
		fmt.Printf("  dead %s %s report=%s command=%s at %s: HTTP %d %s\n",
			d.Meta.ID, d.Meta.Kind, d.Meta.ReportID, d.Meta.CommandID, d.DeadAt.Format(time.RFC3339), d.Status, d.Reason)
	}
	return 0
}
