package main

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
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
	if int(calls.Load()) != len(autoDetectTools) {
		t.Fatalf("probed %d tools, want %d", calls.Load(), len(autoDetectTools))
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
		{"-tool wins", toolSelection{tool: "semgrep", toolList: "nuclei", daemonCommands: true}, all, []string{"semgrep"}, toolSourceFlag},
		{"SENSOR_TOOLS narrows (an operator allowlist)", toolSelection{toolList: " trivy , nuclei,,", daemonCommands: true}, all, []string{"trivy", "nuclei"}, toolSourceList},
		{"SENSOR_TOOLS naming a missing tool keeps it (reported as not installed)", toolSelection{toolList: "codeql", daemonCommands: true}, all, []string{"codeql"}, toolSourceList},
		{"config file", toolSelection{configured: fromFile, toolList: "nuclei", daemonCommands: true}, all, []string{"trivy-image"}, toolSourceConfig},
		{"daemon without a list: every installed tool", toolSelection{daemonCommands: true}, installedOnly("trivy", "nuclei"), []string{"trivy", "nuclei"}, toolSourceDetected},
		{"daemon, nothing installed", toolSelection{daemonCommands: true}, installedOnly(), nil, toolSourceDetected},
		{"one-shot without a list: nothing (no probing)", toolSelection{}, func(context.Context, string) bool { t.Fatal("probed"); return false }, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, source := selectScanners(ctx, tc.in, tc.detect)
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
