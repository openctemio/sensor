package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/toolrun"
)

// installedOnly is a detector that knows which tools are installed.
func installedOnly(names ...string) func(context.Context, string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(_ context.Context, name string) bool { return set[name] }
}

func TestDetectInstalledTools(t *testing.T) {
	var calls atomic.Int32
	check := func(ctx context.Context, name string) bool {
		calls.Add(1)
		return name == "nuclei" || name == "semgrep"
	}
	got := detectInstalledTools(context.Background(), check)
	// Canonical order whatever order the probes finish in.
	if want := []string{"semgrep", "nuclei"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("detected %v, want %v", got, want)
	}
	if int(calls.Load()) != len(discoverableTools()) {
		t.Fatalf("probed %d tools, want %d", calls.Load(), len(discoverableTools()))
	}
	if got := detectInstalledTools(context.Background(), installedOnly()); len(got) != 0 {
		t.Fatalf("nothing installed: %v", got)
	}
}

func TestSelectScanners(t *testing.T) {
	ctx := context.Background()
	all := installedOnly("semgrep", "betterleaks", "trivy", "nuclei")
	fromFile := []ScannerConfig{{Name: "trivy-image", Enabled: true}}

	cases := []struct {
		name       string
		in         toolSelection
		detect     func(context.Context, string) bool
		want       []string
		wantSource string
	}{
		{"-tool wins", toolSelection{tool: "semgrep", toolList: "nuclei", daemon: true}, all, []string{"semgrep"}, toolSourceFlag},
		{"daemon: SENSOR_TOOLS narrows the detected tools", toolSelection{toolList: " trivy , nuclei,,", daemon: true}, all, []string{"trivy", "nuclei"}, toolSourceNarrowed},
		{"daemon: SENSOR_TOOLS naming a missing tool never advertises it", toolSelection{toolList: "codeql,nuclei", daemon: true}, all, []string{"nuclei"}, toolSourceNarrowed},
		{"daemon: a trivy variant is kept when trivy is installed", toolSelection{toolList: "trivy-fs,trivy-config", daemon: true}, all, []string{"trivy", "trivy-config"}, toolSourceNarrowed},
		{"daemon: a trivy variant is dropped without trivy", toolSelection{toolList: "trivy-image", daemon: true}, installedOnly("nuclei"), nil, toolSourceNarrowed},
		{"config file", toolSelection{configured: fromFile, toolList: "nuclei", daemon: true}, all, []string{"trivy-image"}, toolSourceConfig},
		{"daemon without a list: every installed tool", toolSelection{daemon: true}, installedOnly("trivy", "nuclei"), []string{"trivy", "nuclei"}, toolSourceDetected},
		{"daemon, nothing installed", toolSelection{daemon: true}, installedOnly(), nil, toolSourceDetected},
		{"one-shot: the list as given (no probing)", toolSelection{toolList: "codeql"}, func(context.Context, string) bool { t.Fatal("probed"); return false }, []string{"codeql"}, toolSourceList},
		{"one-shot without a list: nothing (no probing)", toolSelection{}, func(context.Context, string) bool { t.Fatal("probed"); return false }, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, source, _ := selectScanners(ctx, tc.in, tc.detect)
			if names := scannerNames(got); !reflect.DeepEqual(names, tc.want) && (len(names) != 0 || len(tc.want) != 0) {
				t.Fatalf("scanners = %v, want %v", names, tc.want)
			}
			if source != tc.wantSource {
				t.Fatalf("source = %q, want %q", source, tc.wantSource)
			}
			for _, s := range got {
				if !s.Enabled {
					t.Fatalf("%s not enabled", s.Name)
				}
			}
		})
	}
}

func TestContentScannersDefault(t *testing.T) {
	ctx := context.Background()
	if got := scannerNames(contentScanners(ctx, "trivy,nuclei", installedOnly())); !reflect.DeepEqual(got, []string{"trivy", "nuclei"}) {
		t.Fatalf("explicit list: %v", got)
	}
	// No list: the installed tools.
	if got := scannerNames(contentScanners(ctx, "", installedOnly("nuclei"))); !reflect.DeepEqual(got, []string{"nuclei"}) {
		t.Fatalf("detected: %v", got)
	}
	// Nothing installed: the content tools, so -content-status still explains.
	if got := scannerNames(contentScanners(ctx, "", installedOnly())); !reflect.DeepEqual(got, []string{"trivy", "nuclei", "semgrep"}) {
		t.Fatalf("fallback: %v", got)
	}
}

// The ignored entries of a narrowing list are the ones not installed or not
// native tools; duplicates and retired names are folded.
func TestNarrowTools(t *testing.T) {
	kept, ignored := narrowTools([]string{"trivy", "nuclei", "rdap"}, "nuclei, NUCLEI, gitleaks, trivy-full, rdap, made-up")
	if want := []string{"nuclei", "trivy-full", "rdap"}; !reflect.DeepEqual(kept, want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	if want := []string{"gitleaks", "made-up"}; !reflect.DeepEqual(ignored, want) {
		t.Fatalf("ignored %v, want %v", ignored, want)
	}
}

// One table: every discoverable tool builds through getScanner under its
// own name, aliases build too, and -list-tools prints the same table.
func TestNativeToolsAreTheOneSource(t *testing.T) {
	seen := map[string]bool{}
	for _, nt := range nativeTools {
		if seen[nt.name] {
			t.Fatalf("%s listed twice", nt.name)
		}
		seen[nt.name] = true
		s, err := getScanner(ScannerConfig{Name: nt.name, Enabled: true}, false)
		if err != nil || s == nil {
			t.Fatalf("%s: getScanner: %v", nt.name, err)
		}
		if _, isPreset := s.(*core.BaseScanner); isPreset {
			t.Fatalf("%s fell through to a preset scanner", nt.name)
		}
		for _, a := range nt.aliases {
			if got, ok := lookupNativeTool(a); !ok || got.name != nt.name {
				t.Fatalf("alias %s does not build %s", a, nt.name)
			}
		}
	}
	for _, name := range recon.Tools {
		if !slices.Contains(discoverableTools(), name) {
			t.Errorf("recon tool %s is not discoverable", name)
		}
	}
	// Every contract tool registered in this build is either a native tool
	// or deliberately not a daemon scanner.
	notDaemonScanners := map[string]bool{"codeql": true, "nuclei-validate": true}
	for _, tl := range toolrun.Registered() {
		name := tl.Manifest().Name
		if _, ok := lookupNativeTool(name); !ok && !notDaemonScanners[name] {
			t.Errorf("registered tool %s is neither in nativeTools nor listed as not a daemon scanner", name)
		}
	}
}

// The tool probe decides: a native tool whose preflight fails is not
// enabled, one whose preflight passes is, with no list involved.
func TestDiscoveryFollowsThePreflight(t *testing.T) {
	probe := func(_ context.Context, name string) bool { return name == "httpx" || name == "rdap" }
	got, source, _ := selectScanners(context.Background(), toolSelection{daemon: true}, probe)
	if names := scannerNames(got); !reflect.DeepEqual(names, []string{"httpx", "rdap"}) || source != toolSourceDetected {
		t.Fatalf("scanners %v (%s)", names, source)
	}
}

// A binary that answers its version check is detected; a missing one is
// not: scannerInstalled runs the real preflight against fake binaries.
func TestScannerInstalledWithFakeBinaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script binaries")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'v1.2.3'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "dnsx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if !scannerInstalled(context.Background(), "dnsx") {
		t.Fatal("a dnsx that answers its version check is not detected")
	}
	if scannerInstalled(context.Background(), "katana") {
		t.Fatal("a missing katana is detected")
	}
	if !scannerInstalled(context.Background(), "rdap") {
		t.Fatal("the compiled-in rdap is not detected")
	}
}

// The deprecated list in a daemon warns, names what it ignored, and logs
// the narrowed selection.
func TestReportToolSelection(t *testing.T) {
	var out, errw bytes.Buffer
	reportToolSelection(&out, &errw, toolSourceNarrowed, []string{"nuclei"}, []string{"codeql"})
	if !strings.Contains(errw.String(), "deprecated") || !strings.Contains(errw.String(), "codeql") ||
		!strings.Contains(out.String(), "Tools: nuclei") {
		t.Fatalf("out=%q err=%q", out.String(), errw.String())
	}
	out.Reset()
	errw.Reset()
	reportToolSelection(&out, &errw, toolSourceDetected, []string{"nuclei"}, nil)
	if strings.Contains(errw.String(), "deprecated") {
		t.Fatalf("no list, yet: %q", errw.String())
	}
}
