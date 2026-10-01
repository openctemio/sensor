package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sensor/internal/tools"
)

// nativeScanner is a scanner -list-tools describes and probes.
type nativeScanner struct {
	name        string
	description string
}

// nativeScanners are the scanners with a native integration (getScanner).
var nativeScanners = []nativeScanner{
	{"semgrep", "SAST scanner with dataflow/taint tracking"},
	{"betterleaks", "Secret detection scanner (replaces gitleaks)"},
	{"trivy", "SCA vulnerability scanner (filesystem)"},
	{"trivy-config", "IaC misconfiguration scanner"},
	{"trivy-image", "Container image scanner"},
	{"trivy-full", "Full scanner (vuln + misconfig + secret)"},
	{"nuclei", "Vulnerability scanner (DAST)"},
}

// toolProbeTimeout bounds one `<tool> --version` run.
const toolProbeTimeout = 30 * time.Second

// probeTool reports whether a scanner's binary is available here, missing,
// or installed but failing to run.
func probeTool(scanner string) tools.Status {
	ctx, cancel := context.WithTimeout(context.Background(), toolProbeTimeout)
	defer cancel()
	return tools.Probe(ctx, tools.BinaryFor(scanner))
}

// unavailableReason explains why a configured scanner cannot be used. A
// binary that is missing and one that is installed but fails to run are
// different problems: the second one is a broken image or host and is
// reported with the tool's own error output, so it is never mistaken for an
// optional tool that simply is not there.
func unavailableReason(ctx context.Context, cfg ScannerConfig, checkErr error) string {
	binary := cfg.Binary
	if binary == "" {
		binary = tools.BinaryFor(cfg.Name)
	}
	pctx, cancel := context.WithTimeout(ctx, toolProbeTimeout)
	defer cancel()
	st := tools.Probe(pctx, binary)
	switch st.State {
	case tools.NotInstalled:
		return fmt.Sprintf("not installed (%v)", st.Err)
	case tools.Broken:
		return fmt.Sprintf("installed but fails to run: %v", st.Err)
	default:
		// `--version` works, but the scanner's own check failed.
		if checkErr != nil {
			return fmt.Sprintf("installed (%s) but its check failed: %v", st.Version, checkErr)
		}
		return fmt.Sprintf("installed (%s) but its check failed", st.Version)
	}
}

// errDaemonNeedsPlatform is returned when a server-controlled daemon has no
// platform URL or API key.
var errDaemonNeedsPlatform = errors.New("a server-controlled daemon (-daemon -enable-commands) needs the platform URL and a sensor API key")

// checkDaemonCredentials refuses to start a server-controlled daemon that
// cannot reach the platform. Without this the daemon started, never polled
// and never said why.
func checkDaemonCredentials(daemon, standalone, enableCommands bool, apiURL, apiKey string) error {
	if !daemon || standalone || !enableCommands {
		return nil
	}
	var missing []string
	if apiURL == "" {
		missing = append(missing, "API_URL")
	}
	if apiKey == "" {
		missing = append(missing, "API_KEY")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w; missing: %v.\n"+
		"  Set them as environment variables (docker run -e API_URL=https://<platform>/ -e API_KEY=<key> ...),\n"+
		"  as -api-url / -api-key flags, or as api.base_url / api.api_key in the -config file.\n"+
		"  Create the key in the platform: Settings > Sensors (it is shown once).\n"+
		"  To scan without a platform, run a one-shot scan instead: -tool <name> -target <path>",
		errDaemonNeedsPlatform, missing)
}
