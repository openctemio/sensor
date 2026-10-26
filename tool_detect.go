package main

// Which scanners the sensor runs. Only the sensor knows what is installed in
// its image or on its host, so the daemon runs every native scanner whose
// wrapper is in this build and whose binary passes its check, and reports
// exactly those to the platform (api RFC-029 §4.3.1): nobody declares a
// sensor's tools. SENSOR_TOOLS (or -tools) is deprecated: in a daemon it only
// narrows the detected tools; the local policy's tools.allow is the
// host owner's way to narrow them.

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/content"
	"github.com/openctemio/sensor/internal/lookup/asn"
	"github.com/openctemio/sensor/internal/lookup/rdap"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/scanners"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/tools"
)

// nativeTool is a scanner with a native integration in this build. The
// nativeTools table is the one list getScanner builds from, the daemon
// detects from and -list-tools prints, so the three cannot drift.
type nativeTool struct {
	name        string
	description string
	// aliases are other names that build this tool ("trivy-fs").
	aliases []string
	// alias marks a variant that runs another entry's binary (trivy-config
	// runs trivy): it is not probed on its own, an operator selects it.
	alias bool
	// builtin: compiled into the sensor, no binary to look for.
	builtin bool
	build   func(cfg ScannerConfig, verbose bool) (core.Scanner, error)
}

// nativeTools are the native scanners, in the order a daemon reports them.
// The image variant decides which binaries are there; a tool is enabled
// only when its binary answers its version check. The passive lookup tools
// (rdap, asn) are compiled in: every image has them.
var nativeTools = []nativeTool{
	{name: "opengrep", description: "SAST scanner with dataflow/taint tracking (local rules only)", build: buildOpengrep},
	{name: "semgrep", description: "SAST scanner with dataflow/taint tracking", build: buildSemgrep},
	{name: core.ScannerBetterleaks, description: "Secret detection scanner (replaces gitleaks)", build: buildBetterleaks},
	{name: "trivy", description: "SCA vulnerability scanner (filesystem)", aliases: []string{"trivy-fs"}, build: buildTrivy(scanners.TrivyFS)},
	{name: "trivy-config", description: "IaC misconfiguration scanner", alias: true, build: buildTrivy(scanners.TrivyConfig)},
	{name: "trivy-image", description: "Container image scanner", alias: true, build: buildTrivy(scanners.TrivyImage)},
	{name: "trivy-full", description: "Full scanner (vuln + misconfig + secret)", alias: true, build: buildTrivy(scanners.TrivyFull)},
	{name: "nuclei", description: "Vulnerability scanner (DAST)", build: buildNuclei},
	{name: "subfinder", description: "Passive subdomain enumeration (recon)", build: buildRecon},
	{name: "dnsx", description: "DNS resolution and records (recon)", build: buildRecon},
	{name: "dnsx-enum", description: "Subdomain brute force with a label list from the job (recon, active)", build: buildRecon},
	{name: "naabu", description: "Port scanner, TCP connect (recon)", build: buildRecon},
	{name: "httpx", description: "HTTP/TLS probe and fingerprinting (recon)", build: buildRecon},
	{name: "katana", description: "Web crawler for endpoint discovery (recon)", build: buildRecon},
	{name: "rdap", description: "Registration data lookup (passive, compiled in)", builtin: true, build: func(ScannerConfig, bool) (core.Scanner, error) { return rdap.NewScanner(), nil }},
	{name: "asn", description: "Network and ASN lookup (passive, compiled in)", builtin: true, build: func(ScannerConfig, bool) (core.Scanner, error) { return asn.NewScanner(), nil }},
}

// lookupNativeTool returns the native tool a (canonical) name builds.
func lookupNativeTool(name string) (nativeTool, bool) {
	name = strings.ToLower(core.CanonicalScannerName(strings.TrimSpace(name)))
	for _, t := range nativeTools {
		if t.name == name || slices.Contains(t.aliases, name) {
			return t, true
		}
	}
	return nativeTool{}, false
}

// discoverableTools are the native tools a daemon probes, in report order.
func discoverableTools() []string {
	var out []string
	for _, t := range nativeTools {
		if !t.alias {
			out = append(out, t.name)
		}
	}
	return out
}

func buildOpengrep(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	scanner := scanners.Opengrep()
	scanner.Verbose = verbose
	if cfg.Binary != "" {
		scanner.Binary = cfg.Binary
	}
	// The local rules path the content manager installs: a one-shot run
	// (no daemon-installed content) runs it as is. When managed content
	// is current, the content wrapper runs the verified copy instead.
	if p := strings.TrimSpace(os.Getenv(content.EnvSemgrepRulesPath)); p != "" {
		scanner.Configs = []string{p}
	}
	return scanner, nil
}

func buildSemgrep(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	scanner := scanners.Semgrep()
	scanner.Verbose = verbose
	if cfg.Binary != "" {
		scanner.Binary = cfg.Binary
	}
	// As for opengrep: the local rules path the content manager installs;
	// semgrep never fetches registry rules itself.
	if p := strings.TrimSpace(os.Getenv(content.EnvSemgrepRulesPath)); p != "" {
		scanner.Configs = []string{p}
	}
	return scanner, nil
}

func buildBetterleaks(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	scanner := scanners.Betterleaks()
	scanner.Verbose = verbose
	if cfg.Binary != "" {
		scanner.Binary = cfg.Binary
	}
	// Wrap betterleaks in adapter to implement core.Scanner
	return &betterleaksAdapter{scanner}, nil
}

func buildTrivy(mk func() *scanners.TrivyScanner) func(ScannerConfig, bool) (core.Scanner, error) {
	return func(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
		scanner := mk()
		scanner.Verbose = verbose
		if cfg.Binary != "" {
			scanner.Binary = cfg.Binary
		}
		return scanner, nil
	}
}

func buildNuclei(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	scanner := scanners.Nuclei()
	scanner.Verbose = verbose
	if cfg.Binary != "" {
		scanner.Binary = cfg.Binary
	}
	// The operator's rate-limit ceilings (SENSOR_NUCLEI_MAX_*): no scan
	// runs above them.
	limits, err := nuclei.LimitsFromEnv(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	scanner.Limits = limits
	return scanner, nil
}

// buildRecon builds a recon tool (api RFC-036 EASM discovery): its results
// are assets, returned as a CTIS report the generic parser reads.
func buildRecon(cfg ScannerConfig, verbose bool) (core.Scanner, error) {
	scanner, err := recon.New(core.CanonicalScannerName(cfg.Name))
	if err != nil {
		return nil, err
	}
	setReconOptions(scanner.Recon(), cfg.Binary, verbose)
	return scanner, nil
}

// Where the scanner list came from (logged at start-up).
const (
	toolSourceConfig   = "config file"
	toolSourceFlag     = "-tool"
	toolSourceList     = "SENSOR_TOOLS / -tools"
	toolSourceDetected = "detected"
	// toolSourceNarrowed: detected, then narrowed by the deprecated
	// SENSOR_TOOLS / -tools list (daemon).
	toolSourceNarrowed = "detected, narrowed by SENSOR_TOOLS / -tools"
)

// toolSelection is what the operator configured.
type toolSelection struct {
	// configured are the scanners of the -config file.
	configured []ScannerConfig
	// tool is -tool; toolList is -tools or SENSOR_TOOLS.
	tool, toolList string
	// daemon is true for the daemon (the default mode): it always detects
	// the installed tools; toolList then only narrows them.
	daemon bool
}

// selectScanners returns the scanners to run, where the list came from and
// the -tools / SENSOR_TOOLS entries a daemon ignored (not installed or
// unknown): the config file, -tool, or, in a daemon, every installed native
// scanner (narrowed by the deprecated list when one is set). A one-shot run
// takes the list as given; without one it gets none ("").
func selectScanners(ctx context.Context, sel toolSelection, installed func(context.Context, string) bool) ([]ScannerConfig, string, []string) {
	switch {
	case len(sel.configured) > 0:
		return sel.configured, toolSourceConfig, nil
	case strings.TrimSpace(sel.tool) != "":
		return []ScannerConfig{{Name: strings.TrimSpace(sel.tool), Enabled: true}}, toolSourceFlag, nil
	case sel.daemon:
		detected := detectInstalledTools(ctx, installed)
		if strings.TrimSpace(sel.toolList) == "" {
			return parseToolList(strings.Join(detected, ",")), toolSourceDetected, nil
		}
		kept, ignored := narrowTools(detected, sel.toolList)
		return parseToolList(strings.Join(kept, ",")), toolSourceNarrowed, ignored
	case strings.TrimSpace(sel.toolList) != "":
		return parseToolList(sel.toolList), toolSourceList, nil
	default:
		return nil, "", nil
	}
}

// narrowTools applies the deprecated SENSOR_TOOLS / -tools list to the
// detected tools: it keeps the listed ones that are installed, in list
// order, and a listed variant of an installed tool's binary ("trivy-fs",
// "trivy-config" when trivy is installed). Every other entry (not
// installed, or not a native tool) is returned as ignored: the list never
// makes the sensor advertise a tool it cannot run.
func narrowTools(detected []string, list string) (kept, ignored []string) {
	seen := map[string]bool{}
	for _, sc := range parseToolList(list) {
		nt, ok := lookupNativeTool(sc.Name)
		if !ok {
			ignored = append(ignored, sc.Name)
			continue
		}
		if seen[nt.name] {
			continue
		}
		seen[nt.name] = true
		installed := slices.Contains(detected, nt.name)
		if !installed && nt.alias {
			bin := tools.BinaryFor(nt.name)
			installed = slices.ContainsFunc(detected, func(d string) bool { return tools.BinaryFor(d) == bin })
		}
		if !installed {
			ignored = append(ignored, sc.Name)
			continue
		}
		kept = append(kept, nt.name)
	}
	return kept, ignored
}

// reportToolSelection logs the daemon's tool selection: what was detected,
// the deprecated narrowing list and its ignored entries.
func reportToolSelection(out, errw io.Writer, source string, names, ignored []string) {
	switch source {
	case toolSourceDetected, toolSourceNarrowed:
	default:
		return
	}
	if source == toolSourceNarrowed {
		_, _ = fmt.Fprintf(errw, "Warning: %s\n", toolsDeprecatedMsg)
		if len(ignored) > 0 {
			_, _ = fmt.Fprintf(errw, "Warning: SENSOR_TOOLS / -tools names tools that are not installed here (ignored): %s\n", strings.Join(ignored, ", "))
		}
	}
	if len(names) == 0 {
		_, _ = fmt.Fprintf(errw, "Warning: no scanner found here (looked for %s); the platform will send this sensor no scans\n",
			strings.Join(discoverableTools(), ", "))
		return
	}
	_, _ = fmt.Fprintf(out, "  Tools: %s (%s)\n", strings.Join(names, ", "), source)
}

// toolsDeprecatedMsg is the daemon's warning for SENSOR_TOOLS / -tools.
const toolsDeprecatedMsg = "SENSOR_TOOLS / -tools is deprecated for the daemon: it now only narrows the detected tools and will be removed; " +
	"narrow with the local policy's tools.allow"

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

// detectInstalledTools probes the discoverable native tools (in parallel: a
// version check can take seconds) and returns the installed ones in their
// order.
func detectInstalledTools(ctx context.Context, installed func(context.Context, string) bool) []string {
	names := discoverableTools()
	found := make([]bool, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() { found[i] = installed(ctx, name) })
	}
	wg.Wait()
	var out []string
	for i, name := range names {
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
