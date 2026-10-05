package main

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
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
	{"subfinder", "Passive subdomain enumeration (recon)"},
	{"dnsx", "DNS resolution and records (recon)"},
	{"naabu", "Port scanner, TCP connect (recon)"},
	{"httpx", "HTTP/TLS probe and fingerprinting (recon)"},
	{"katana", "Web crawler for endpoint discovery (recon)"},
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

// daemonCredentialsHelp words the SDK's error for a server-controlled daemon
// started without the platform URL or API key (sensorkit.CheckCredentials).
var daemonCredentialsHelp = sensorkit.CredentialsHelp{
	Subject: "a server-controlled daemon (-daemon -enable-commands)",
	Hint: "  Set API_URL (docker run -e API_URL=https://<platform>/ ..., -api-url, or api.base_url in the -config file).\n" +
		"  Without API_KEY the sensor pairs on first start: it prints a code and a fingerprint for an\n" +
		"  administrator to approve under Sensors > Pair a sensor (or run `openctemio-sensor pair` first).\n" +
		"  To scan without a platform, run a one-shot scan instead: -tool <name> -target <path>",
}
