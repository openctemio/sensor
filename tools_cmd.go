package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
	"github.com/openctemio/sensor/internal/toolrun"
)

// builtinTools are the tools ported to the tool contract (sdk-go pkg/tool):
// each task runs out of process, the sensor re-executing itself as
// "<sensor> __openctem-tool <name>" in the task sandbox. Their manifests
// are compiled in (the signed binary is their source of trust) and
// reported to the platform by digest.
//
// Each tool registers itself in its own package (toolrun.Register); the
// references below make sure those packages are linked in.
func builtinTools() []tool.Tool {
	return toolrun.Registered()
}

var (
	_ = recon.HTTPXTool
	_ = nuclei.Tool
)

// toolManifestEntry is one line of `tools manifests`.
type toolManifestEntry struct {
	Digest   string        `json:"digest"`
	Manifest tool.Manifest `json:"manifest"`
}

// runToolsCommand serves `openctemio-sensor tools manifests [--json]`: the
// manifests of the compiled-in tools with their digests.
func runToolsCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "manifests" {
		_, _ = fmt.Fprintln(stderr, "usage: openctemio-sensor tools manifests [--json]")
		return 2
	}
	asJSON := len(args) > 1 && args[1] == "--json"
	var entries []toolManifestEntry
	for _, t := range builtinTools() {
		m := t.Manifest().Normalized()
		entries = append(entries, toolManifestEntry{Digest: m.Digest(), Manifest: m})
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	for _, e := range entries {
		m := e.Manifest
		_, _ = fmt.Fprintf(stdout, "%-10s %-8s %-12s %s network=%s produces=%v\n  %s\n", m.Name, m.Version, m.Class, m.Tier, m.Permissions.Network, m.Produces, e.Digest)
	}
	return 0
}
