package main

// The ProjectDiscovery recon tools as dispatched scanners (api RFC-036 EASM
// discovery). internal/recon's Scanner runs a tool on each job target and
// returns a CTIS report of the hosts, IPs, services and URLs it found; the
// platform turns them into assets. Targets are validated by the SDK
// executor's scan-target policy (SSRF guard) before the tool sees them, and
// nothing from the job reaches the tool's command line except the targets.
//
// Defaults are non-intrusive (RFC-036 O3, tier T1): naabu is a TCP connect
// scan of the top 100 ports (no raw sockets, no root), httpx sends GETs,
// katana crawls without filling forms, subfinder is passive.

import (
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/recon/dnsx"
	"github.com/openctemio/sensor/internal/recon/httpx"
	"github.com/openctemio/sensor/internal/recon/katana"
	"github.com/openctemio/sensor/internal/recon/naabu"
	"github.com/openctemio/sensor/internal/recon/subfinder"
)

// setReconOptions applies a configured binary path and verbosity to a recon
// tool, and pins naabu to a connect scan whatever its default becomes.
func setReconOptions(rs core.ReconScanner, binary string, verbose bool) {
	switch s := rs.(type) {
	case *subfinder.Scanner:
		s.Verbose = verbose
		if binary != "" {
			s.Binary = binary
		}
	case *dnsx.Scanner:
		s.Verbose = verbose
		if binary != "" {
			s.Binary = binary
		}
	case *naabu.Scanner:
		s.Verbose = verbose
		s.ScanType = naabu.ScanTypeConnect
		if binary != "" {
			s.Binary = binary
		}
	case *httpx.Scanner:
		s.Verbose = verbose
		if binary != "" {
			s.Binary = binary
		}
	case *katana.Scanner:
		s.Verbose = verbose
		s.FormFill = false
		s.Headless = false
		if binary != "" {
			s.Binary = binary
		}
	}
}
