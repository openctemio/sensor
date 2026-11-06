package webshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sensor/internal/toolrun"
)

// Scanner is the core.Scanner the command executor dispatches for webshot:
// it maps a scan's settings to the tool's configuration and runs the tool
// out of process in the task sandbox (the browser sandbox, confined).
type Scanner struct {
	// Browser is the browser binary (default: $OPENCTEM_WEBSHOT_BROWSER,
	// else DefaultBrowser).
	Browser string
}

// NewScanner is the webshot scanner.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) browser() string {
	if s.Browser != "" {
		return s.Browser
	}
	if v := strings.TrimSpace(os.Getenv(EnvBrowser)); v != "" {
		return v
	}
	return DefaultBrowser
}

// Name is the tool's name.
func (s *Scanner) Name() string { return Manifest.Name }

// Version is the tool's version (compiled in).
func (s *Scanner) Version() string { return Manifest.Version }

// Capabilities are the registry words of the tool.
func (s *Scanner) Capabilities() []string { return []string{"recon"} }

// IsInstalled reports the browser's version when the binary answers and the
// sensor's sandbox can run it (required mode, confined network): a sensor
// that cannot run the browser safely does not offer the tool at all.
//
// The daemon detects its tools before it installs the sandbox, so the
// configuration decides: both modes required (the sensor then refuses to
// start where they cannot hold). Once a backend is installed, its status
// must hold as well. The tool host checks again for every task.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	if !sandboxRequired() {
		return false, "", errNeedsSandbox
	}
	if st := executor.Current().Status(); st.Mode != executor.ModeOff &&
		(!st.NetworkEnforced || st.Mode != executor.ModeRequired || !st.Complete()) {
		return false, "", errNeedsSandbox
	}
	v, err := browserVersion(ctx, s.browser())
	if err != nil {
		return false, "", err
	}
	return true, v, nil
}

var errNeedsSandbox = fmt.Errorf("webshot needs the task sandbox in required mode with network confinement (%s=required, %s=required)",
	sensorkit.EnvSandbox, sensorkit.EnvSandboxNetwork)

// sandboxRequired reports whether the sensor is configured to run every
// task in the full sandbox with a confined network (shared mode implies it).
func sandboxRequired() bool {
	if v, _ := sensorkit.SharedModeFromEnv(); v {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv(sensorkit.EnvSandbox)), "required") &&
		strings.EqualFold(strings.TrimSpace(os.Getenv(sensorkit.EnvSandboxNetwork)), "required")
}

// browserVersion runs the browser's --version (no page, no network).
func browserVersion(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // the configured browser binary
	cmd.Stdout = &out
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("webshot: browser %s: %w", bin, err)
	}
	v := strings.TrimSpace(out.String())
	if len(v) > 100 {
		v = v[:100]
	}
	return v, nil
}

// SettingsSchema is the tool's configuration schema.
func (s *Scanner) SettingsSchema() *core.SettingsSchema { return settingsSchema }

// ToolContract names the tool's manifest in the sensor manifest.
func (s *Scanner) ToolContract() *core.ToolContract { return toolrun.Contract(Manifest) }

// EnforcesScopeLimits: the task runs confined, so the forwarder enforces a
// target's port and path limits on every request the browser makes.
func (s *Scanner) EnforcesScopeLimits() bool { return true }

// RoutesEgress: every capture runs out of process through the tool host.
func (s *Scanner) RoutesEgress() bool { return true }

// TakesCapabilityJobs: the tool implements capture.screenshot@1.
func (s *Scanner) TakesCapabilityJobs() bool { return toolrun.TakesJobs(Manifest) }

// Scan captures one target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// ErrExtraArgs: the tool has no command line to add arguments to.
var ErrExtraArgs = errors.New("webshot takes no extra arguments")

// ScanTargets captures every target in one task.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	ctx, opts, err := toolrun.ApplyJob(ctx, Manifest, settingsSchema, opts)
	if err != nil {
		return nil, err
	}
	local := Local{Browser: s.browser()}
	if opts != nil {
		if len(opts.ExtraArgs) > 0 {
			return nil, ErrExtraArgs
		}
		if opts.Settings != nil {
			if opts.Settings.SchemaDigest() != settingsSchema.Digest() {
				return nil, errors.New("webshot settings: resolved against another schema")
			}
			if local.Config, err = configFrom(opts.Settings); err != nil {
				return nil, fmt.Errorf("webshot settings: %w", err)
			}
		}
	}
	res, _, err := toolrun.Run(ctx, Tool, targets, local, toolhost.RunOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return res, nil
}

func configFrom(ts *core.ToolSettings) (json.RawMessage, error) {
	var c Config
	if v, ok := ts.Int("page_timeout"); ok {
		c.PageTimeout = int(v)
	}
	if v, ok := ts.Bool("full_page"); ok {
		c.FullPage = v
	}
	if v, ok := ts.Int("max_requests"); ok {
		c.MaxRequests = int(v)
	}
	if v, ok := ts.Int("max_image_kb"); ok {
		c.MaxImageKB = int(v)
	}
	return json.Marshal(c)
}
