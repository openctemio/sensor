package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/recon"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/recon/subfinder"
)

// The platform's tool catalog (api migration 000055) gives each recon tool
// these capabilities; a job requiring them is offered only to a sensor
// that advertises them.
var catalogCapabilities = map[string][]string{
	"subfinder": {"recon", "subdomain"},
	"dnsx":      {"recon", "dns"},
	"naabu":     {"recon", "portscan"},
	"httpx":     {"recon", "http", "tech_detect"},
	"katana":    {"recon", "crawler", "url_discovery"},
}

func TestGetScanner_ReconTools(t *testing.T) {
	for name, caps := range catalogCapabilities {
		s, err := getScanner(ScannerConfig{Name: name, Enabled: true}, false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Name() != name {
			t.Errorf("%s: name %q", name, s.Name())
		}
		if !reflect.DeepEqual(s.Capabilities(), caps) {
			t.Errorf("%s: capabilities %v, want %v", name, s.Capabilities(), caps)
		}
		if _, ok := s.(core.MultiTargetScanner); !ok {
			t.Errorf("%s: not a multi-target scanner", name)
		}
		if !slices.Contains(autoDetectTools, name) {
			t.Errorf("%s is not auto-detected", name)
		}
	}
}

// Non-intrusive defaults (RFC-036 O3): naabu connect scan, katana without
// form filling or a headless browser.
func TestGetScanner_ReconNonIntrusive(t *testing.T) {
	s, _ := getScanner(ScannerConfig{Name: "naabu", Enabled: true}, false)
	if n := s.(*recon.Scanner).Recon().(*naabu.Scanner); n.ScanType != naabu.ScanTypeConnect {
		t.Errorf("naabu scan type %q, want connect", n.ScanType)
	}
	s, _ = getScanner(ScannerConfig{Name: "katana", Enabled: true}, false)
	if k := s.(*recon.Scanner).Recon().(*katana.Scanner); k.FormFill || k.Headless {
		t.Errorf("katana form fill %v headless %v", k.FormFill, k.Headless)
	}
	s, _ = getScanner(ScannerConfig{Name: "subfinder", Enabled: true, Binary: "/opt/sf"}, false)
	if b := s.(*recon.Scanner).Recon().(*subfinder.Scanner).Binary; b != "/opt/sf" {
		t.Errorf("binary %q", b)
	}
}

// fakeTool writes an executable named name that runs script.
func fakeTool(t *testing.T, dir, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fake")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

// A sensor advertises a recon tool only when its binary answers -version;
// one that is on PATH but does not run is not advertised.
func TestScannerInstalled_ReconNeedsAWorkingBinary(t *testing.T) {
	dir := t.TempDir()
	fakeTool(t, dir, "subfinder", `[ "$1" = "-version" ] && { echo "[INF] Current Version: v2.16.0" >&2; exit 0; }; exit 1`+"\n")
	fakeTool(t, dir, "dnsx", "exit 1\n")
	t.Setenv("PATH", dir)
	ctx := context.Background()
	if !scannerInstalled(ctx, "subfinder") {
		t.Error("working subfinder not detected")
	}
	if scannerInstalled(ctx, "dnsx") {
		t.Error("broken dnsx detected")
	}
	if scannerInstalled(ctx, "httpx") {
		t.Error("missing httpx detected")
	}
	got := detectInstalledTools(ctx, scannerInstalled)
	// The compiled-in lookup tools are always there.
	if !slices.Equal(got, []string{"subfinder", "rdap", "asn"}) {
		t.Errorf("detected %v", got)
	}
}

// A dispatched subfinder job yields subdomain assets in a report the
// command executor's generic parser reads.
func TestReconScan_ReportsAssets(t *testing.T) {
	dir := t.TempDir()
	fakeTool(t, dir, "subfinder", `case "$*" in
*-version*) echo "[INF] Current Version: v2.16.0" >&2 ;;
*) echo '{"host":"api.example.com","input":"example.com","source":"crtsh"}'
   echo '{"host":"www.example.com","input":"example.com","source":"crtsh"}' ;;
esac
`)
	t.Setenv("PATH", dir)
	s, err := getScanner(ScannerConfig{Name: "subfinder", Enabled: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := s.Scan(ctx, "example.com", &core.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reg := newParserRegistryWith(nil)
	p, err := reg.ForScanner("subfinder", res.RawOutput)
	if err != nil {
		t.Fatal(err)
	}
	report, err := p.Parse(ctx, res.RawOutput, &core.ParseOptions{ToolName: "subfinder"})
	if err != nil {
		t.Fatal(err)
	}
	var subs []string
	for _, a := range report.Assets {
		if a.Type == ctis.AssetTypeSubdomain {
			subs = append(subs, a.Value)
		}
	}
	slices.Sort(subs)
	if !slices.Equal(subs, []string{"api.example.com", "www.example.com"}) {
		t.Fatalf("subdomains %v (report %s)", subs, res.RawOutput)
	}
}

// A tool that exits non-zero fails the job instead of completing it with
// no assets.
func TestReconScan_FailedRunFailsTheJob(t *testing.T) {
	dir := t.TempDir()
	fakeTool(t, dir, "dnsx", `echo "flag provided but not defined: -rw" >&2; exit 2`+"\n")
	t.Setenv("PATH", dir)
	s, _ := getScanner(ScannerConfig{Name: "dnsx", Enabled: true}, false)
	if _, err := s.Scan(context.Background(), "example.com", &core.ScanOptions{}); err == nil {
		t.Fatal("a failed dnsx run did not fail the job")
	}
}
