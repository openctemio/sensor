package main

// Which scanners the sensor runs. Only the sensor knows what is installed in
// its image or on its host, so a server-controlled daemon given no tool list
// runs every native scanner it finds and reports exactly those to the
// platform (api RFC-029 §4.3.1): nobody declares a sensor's tools on the
// platform. SENSOR_TOOLS (or -tools) is optional: an operator allowlist that
// narrows what the sensor runs and reports.

import (
	"context"
	"strings"
	"sync"
)

// autoDetectTools are the native scanners a daemon looks for, in the order
// it reports them. The image variant decides which are there: the -default
// (platform) and full images have all nine binaries, a single-tool image
// has one. A tool is reported only when its binary answers its version
// flag, so a sensor never advertises a recon capability it cannot run. The
// passive lookup tools (rdap, asn) are compiled in: every image has them.
var autoDetectTools = []string{"semgrep", "betterleaks", "trivy", "nuclei", "subfinder", "dnsx", "naabu", "httpx", "katana", "rdap", "asn"}

// Where the scanner list came from (logged at start-up).
const (
	toolSourceConfig   = "config file"
	toolSourceFlag     = "-tool"
	toolSourceList     = "SENSOR_TOOLS / -tools"
	toolSourceDetected = "detected"
)

// toolSelection is what the operator configured.
type toolSelection struct {
	// configured are the scanners of the -config file.
	configured []ScannerConfig
	// tool is -tool; toolList is -tools or SENSOR_TOOLS.
	tool, toolList string
	// daemonCommands is true for a server-controlled daemon (-daemon
	// -enable-commands): the only mode that detects tools.
	daemonCommands bool
}

// selectScanners returns the scanners to run and where the list came from:
// the config file, -tool, the -tools / SENSOR_TOOLS list, or (a
// server-controlled daemon given none of them) every installed native
// scanner. Other modes without a list get none ("").
func selectScanners(ctx context.Context, sel toolSelection, installed func(context.Context, string) bool) ([]ScannerConfig, string) {
	switch {
	case len(sel.configured) > 0:
		return sel.configured, toolSourceConfig
	case strings.TrimSpace(sel.tool) != "":
		return []ScannerConfig{{Name: strings.TrimSpace(sel.tool), Enabled: true}}, toolSourceFlag
	case strings.TrimSpace(sel.toolList) != "":
		return parseToolList(sel.toolList), toolSourceList
	case sel.daemonCommands:
		return parseToolList(strings.Join(detectInstalledTools(ctx, installed), ",")), toolSourceDetected
	default:
		return nil, ""
	}
}

// parseToolList turns "a, b,,c" into enabled scanner configs.
func parseToolList(list string) []ScannerConfig {
	var out []ScannerConfig
	for t := range strings.SplitSeq(list, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, ScannerConfig{Name: t, Enabled: true})
		}
	}
	return out
}

// detectInstalledTools probes the autoDetectTools (in parallel: a version
// check can take seconds) and returns the installed ones in their order.
func detectInstalledTools(ctx context.Context, installed func(context.Context, string) bool) []string {
	found := make([]bool, len(autoDetectTools))
	var wg sync.WaitGroup
	for i, name := range autoDetectTools {
		wg.Go(func() { found[i] = installed(ctx, name) })
	}
	wg.Wait()
	var out []string
	for i, name := range autoDetectTools {
		if found[i] {
			out = append(out, name)
		}
	}
	return out
}

// scannerInstalled reports whether a native scanner's binary is installed
// and its own check passes.
func scannerInstalled(ctx context.Context, name string) bool {
	scanner, err := getScanner(ScannerConfig{Name: name, Enabled: true}, false)
	if err != nil || scanner == nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, toolProbeTimeout)
	defer cancel()
	ok, _, err := scanner.IsInstalled(pctx)
	return ok && err == nil
}

// contentScanners are the scanners -content-status / -content-refresh look
// at: the given list, else the installed tools, else the content tools
// (so the command still says what it would manage).
func contentScanners(ctx context.Context, toolList string, installed func(context.Context, string) bool) []ScannerConfig {
	if sc := parseToolList(toolList); len(sc) > 0 {
		return sc
	}
	if sc := parseToolList(strings.Join(detectInstalledTools(ctx, installed), ",")); len(sc) > 0 {
		return sc
	}
	return parseToolList("trivy,nuclei,semgrep")
}

// scannerNames returns the scanners' names.
func scannerNames(sc []ScannerConfig) []string {
	out := make([]string, 0, len(sc))
	for _, s := range sc {
		out = append(out, s.Name)
	}
	return out
}
