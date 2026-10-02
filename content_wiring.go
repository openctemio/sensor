package main

// Scanner content management (internal/content): the trivy database, the
// nuclei templates and the semgrep rules are refreshed, verified and swapped
// by the sensor, and every scan runs on the version current when it starts.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sensor/internal/content"
)

// contentTools returns the canonical names of the enabled scanners' tools,
// in configuration order, without duplicates.
func contentTools(scanners []ScannerConfig) ([]string, content.Tools) {
	var names []string
	var t content.Tools
	seen := map[string]bool{}
	for _, s := range scanners {
		if !s.Enabled {
			continue
		}
		name := content.ToolOf(core.CanonicalScannerName(s.Name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
		switch name {
		case "trivy":
			t.Trivy = true
		case "nuclei":
			t.Nuclei = true
		case "semgrep":
			t.Semgrep = true
		}
	}
	return names, t
}

// newContentManager builds the content manager for the configured scanners.
// It returns nil when content management is off (SENSOR_CONTENT=off) or no
// configured tool uses content. readOnly (one-shot runs) only uses content a
// daemon installed: it returns nil when the content directory does not exist.
func newContentManager(scanners []ScannerConfig, verbose, readOnly bool) (*content.Manager, error) {
	settings, err := content.SettingsFromEnv(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	if !settings.Enabled {
		return nil, nil
	}
	if readOnly {
		if _, err := os.Stat(settings.Root); err != nil {
			return nil, nil
		}
	}
	_, used := contentTools(scanners)
	if settings.TrivyJavaDB && used.Trivy {
		// The sensor refreshes the Java DB; scans must not download another.
		_ = os.Setenv("TRIVY_SKIP_JAVA_DB_UPDATE", "true")
	}
	return content.NewFromSettings(settings, used, verbose)
}

// daemonContent plugs the content manager into the SDK's sensor runtime
// (sensorkit.Content): every heartbeat carries each tool's content
// (Decorate), refreshes run in the background (Start), and dispatched scans'
// results carry the content they used (WrapPusher).
type daemonContent struct{ m *content.Manager }

var (
	_ sensorkit.Content        = daemonContent{}
	_ sensorkit.ContentStarter = daemonContent{}
	_ sensorkit.PusherWrapper  = daemonContent{}
)

func (c daemonContent) Decorate(r core.CapabilityReport) core.CapabilityReport {
	return c.m.Decorate(r)
}

func (c daemonContent) Start(ctx context.Context) { startContent(ctx, c.m) }

func (c daemonContent) WrapPusher(p core.Pusher) core.Pusher {
	return &content.Pusher{Pusher: p, Manager: c.m}
}

// startContent starts scheduled refreshes.
func startContent(ctx context.Context, m *content.Manager) {
	if m == nil {
		return
	}
	go m.Run(ctx)
	fmt.Printf("  Scanner content: managed in %s (%v)\n", m.Root(), m.Names())
}

// runContentCommand serves -content-status and -content-refresh: the
// content of the tools in toolList (all content-using tools when empty).
func runContentCommand(toolList string, refresh, force, verbose bool) int {
	if err := applyEgressSettings(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return sensorkit.ExitCode(err)
	}
	scanners := contentScanners(context.Background(), toolList, scannerInstalled)
	m, err := newContentManager(scanners, verbose, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if m == nil {
		fmt.Fprintln(os.Stderr, "Scanner content management is off (SENSOR_CONTENT=off) or no configured tool uses content.")
		return 1
	}
	code := 0
	if refresh {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		for _, r := range m.Refresh(ctx, nil, force) {
			switch {
			case r.Err != nil:
				code = 1
				fmt.Fprintf(os.Stderr, "%s: refresh failed: %v\n", r.Name, r.Err)
			case r.Refreshed:
				fmt.Printf("%s: refreshed\n", r.Name)
			case r.Skipped:
				fmt.Printf("%s: not managed\n", r.Name)
			default:
				fmt.Printf("%s: unchanged\n", r.Name)
			}
		}
	}
	out, _ := json.MarshalIndent(map[string]any{"root": m.Root(), "content": m.Content()}, "", "  ")
	fmt.Println(string(out))
	return code
}

// applyEgressSettings applies the CA and proxy settings that sensorkit.New
// applies (SENSOR_CA_CERT_FILE, SENSOR_CONTROL_PROXY, SENSOR_CONTENT_PROXY,
// SENSOR_SCAN_PROXY; api RFC-034), for the content commands, which run
// without the kit.
func applyEgressSettings() error {
	if f := os.Getenv(sensorkit.EnvCACertFile); f != "" {
		pool, err := httpsec.LoadCAFile(f)
		if err != nil {
			return err
		}
		httpsec.SetAPIRootCAs(pool)
		httpsec.SetContentRootCAs(pool)
	}
	p, err := sensorkit.ResolveProxies(sensorkit.ProxyOptions{})
	if err != nil {
		return err
	}
	p.Apply()
	fmt.Fprintln(os.Stderr, p.Summary())
	return nil
}
