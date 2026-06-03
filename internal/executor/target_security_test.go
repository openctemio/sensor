package executor

import (
	"net"
	"strings"
	"testing"
)

// Tests for the two-tier scanner-target SSRF guard introduced in
// the 2026-04 audit batch. Focus on the hard-vs-soft split: no env
// var (not even a deliberately-flipped allowPrivateTargets) may
// open the hard-blocked CIDRs — that is the whole reason the split
// exists.

func TestMain(m *testing.M) {
	// Pin the production posture regardless of whatever the harness
	// env carries. Each test flips allowPrivateTargets locally as
	// needed.
	allowPrivateTargets = false
	m.Run()
}

// --- default mode: all private blocked ---

func TestValidateScannerTarget_DefaultMode_BlocksPrivate(t *testing.T) {
	prev := allowPrivateTargets
	allowPrivateTargets = false
	defer func() { allowPrivateTargets = prev }()

	blocked := []string{
		"http://10.0.0.5/",
		"http://192.168.1.10/",
		"http://172.16.5.5/",
		"http://127.0.0.1/",
		"http://169.254.169.254/latest/meta-data/",
	}
	for _, u := range blocked {
		t.Run(u, func(t *testing.T) {
			if err := validateScannerTarget(u); err == nil {
				t.Fatalf("default mode must reject %q", u)
			}
		})
	}
}

func TestValidateScannerTarget_DefaultMode_AllowsPublic(t *testing.T) {
	prev := allowPrivateTargets
	allowPrivateTargets = false
	defer func() { allowPrivateTargets = prev }()

	// Bare IP literals so the test doesn't depend on external DNS.
	public := []string{
		"http://8.8.8.8/",
		"http://1.1.1.1/",
	}
	for _, u := range public {
		if err := validateScannerTarget(u); err != nil {
			t.Errorf("public IP %q must pass: %v", u, err)
		}
	}
}

// --- opt-in mode: RFC1918/ULA pass, hard-blocked stay blocked ---

func TestValidateScannerTarget_AllowPrivate_ScansRFC1918(t *testing.T) {
	prev := allowPrivateTargets
	allowPrivateTargets = true
	defer func() { allowPrivateTargets = prev }()

	allowed := []string{
		"http://10.0.0.5/",      // corp internal
		"http://10.255.255.255", // edge of /8
		"http://172.16.0.1/",    // RFC1918 B
		"http://172.31.255.255", // edge of /12
		"http://192.168.1.10/",  // RFC1918 C
	}
	for _, u := range allowed {
		t.Run(u, func(t *testing.T) {
			if err := validateScannerTarget(u); err != nil {
				t.Errorf("allowPrivate=true: %q should be scannable but was rejected: %v", u, err)
			}
		})
	}
}

// Critical test — the whole reason for the hard/soft split. Even
// after opt-in, scanning cloud-metadata / loopback / CGNAT is still
// refused. If this ever starts passing, the opt-in has become a
// backdoor to credentials-leak territory.
func TestValidateScannerTarget_AllowPrivate_HardBlockedStays(t *testing.T) {
	prev := allowPrivateTargets
	allowPrivateTargets = true
	defer func() { allowPrivateTargets = prev }()

	mustStillFail := []string{
		"http://127.0.0.1/",                        // loopback
		"http://169.254.169.254/latest/meta-data/", // AWS IMDS
		"http://169.254.0.1/",                      // any link-local
		"http://100.64.0.1/",                       // CGNAT
		"http://224.1.2.3/",                        // multicast
		"http://0.0.0.1/",                          // "this" network
	}
	for _, u := range mustStillFail {
		t.Run(u, func(t *testing.T) {
			err := validateScannerTarget(u)
			if err == nil {
				t.Fatalf("allowPrivate=true MUST NOT open %q — IMDS / loopback / CGNAT are always blocked", u)
			}
			// Sanity: error mentions the IP so ops can triage quickly.
			if !strings.Contains(err.Error(), "block") {
				t.Errorf("reject error should mention 'block', got: %v", err)
			}
		})
	}
}

// --- hostname aliases (string-level block) ---

func TestValidateScannerTarget_AliasesBlockedInBothModes(t *testing.T) {
	aliases := []string{
		"http://localhost:8080/",
		"http://metadata.google.internal/",
	}
	for _, mode := range []bool{false, true} {
		t.Run("allowPrivate="+boolString(mode), func(t *testing.T) {
			prev := allowPrivateTargets
			allowPrivateTargets = mode
			defer func() { allowPrivateTargets = prev }()
			for _, u := range aliases {
				if err := validateScannerTarget(u); err == nil {
					t.Errorf("alias %q must be blocked in both modes", u)
				}
			}
		})
	}
}

// --- unknown scheme ---

func TestValidateScannerTarget_RejectsUnsupportedSchemes(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "gopher://evil/", "javascript:alert(1)"} {
		if err := validateScannerTarget(u); err == nil {
			t.Errorf("scheme %q must be rejected", u)
		}
	}
}

// --- empty input ---

func TestValidateScannerTarget_EmptyInputPasses(t *testing.T) {
	if err := validateScannerTarget(""); err != nil {
		t.Errorf("empty target must pass (some scanners run on a list, not -u): %v", err)
	}
}

// --- AllowPrivateTargets exported observability ---

func TestAllowPrivateTargets_ReflectsToggle(t *testing.T) {
	prev := allowPrivateTargets
	defer func() { allowPrivateTargets = prev }()
	allowPrivateTargets = true
	if !AllowPrivateTargets() {
		t.Error("AllowPrivateTargets() should return true when toggled on")
	}
	allowPrivateTargets = false
	if AllowPrivateTargets() {
		t.Error("AllowPrivateTargets() should return false when toggled off")
	}
}

// --- bare-IP path (no DNS round-trip) ---

func TestValidateScannerTarget_BareIP_AllowPrivate(t *testing.T) {
	prev := allowPrivateTargets
	allowPrivateTargets = true
	defer func() { allowPrivateTargets = prev }()
	// Plain IP literal — should route through the "ip := net.ParseIP"
	// branch without a DNS lookup. Pin that the two-tier policy
	// applies identically to bare IPs.
	if err := validateScannerTarget("10.0.0.5"); err != nil {
		t.Errorf("bare RFC1918 IP with allowPrivate=true must pass: %v", err)
	}
	if err := validateScannerTarget("169.254.169.254"); err == nil {
		t.Error("bare IMDS IP must remain blocked")
	}
}

// isBlockedIP direct coverage — exercises the compiled CIDR table.
func TestIsBlockedIP_Matrix(t *testing.T) {
	t.Run("hard-blocked always blocked", func(t *testing.T) {
		prev := allowPrivateTargets
		for _, on := range []bool{false, true} {
			allowPrivateTargets = on
			for _, ip := range []string{"127.0.0.1", "169.254.169.254", "100.64.0.5", "224.1.2.3"} {
				if !isBlockedIP(net.ParseIP(ip)) {
					t.Errorf("allowPrivate=%v: %s MUST be hard-blocked", on, ip)
				}
			}
		}
		allowPrivateTargets = prev
	})

	t.Run("rfc1918 conditional on allowPrivate", func(t *testing.T) {
		prev := allowPrivateTargets
		defer func() { allowPrivateTargets = prev }()
		allowPrivateTargets = false
		if !isBlockedIP(net.ParseIP("10.0.0.1")) {
			t.Error("allowPrivate=false: 10.0.0.1 must be blocked")
		}
		allowPrivateTargets = true
		if isBlockedIP(net.ParseIP("10.0.0.1")) {
			t.Error("allowPrivate=true: 10.0.0.1 must be allowed")
		}
	})

	t.Run("public always allowed", func(t *testing.T) {
		prev := allowPrivateTargets
		defer func() { allowPrivateTargets = prev }()
		for _, on := range []bool{false, true} {
			allowPrivateTargets = on
			if isBlockedIP(net.ParseIP("8.8.8.8")) {
				t.Errorf("allowPrivate=%v: 8.8.8.8 must always pass", on)
			}
		}
	})
}

// --- helpers ---

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestConfineScanPath(t *testing.T) {
	rejected := []string{"", "/", "/etc", "/etc/shadow", "/root", "/root/.ssh/id_rsa", "/proc/1/environ", "/usr/bin", "/var/lib/secrets"}
	for _, p := range rejected {
		if _, err := confineScanPath(p); err == nil {
			t.Errorf("confineScanPath(%q): expected rejection, got nil error", p)
		}
	}
	allowed := []string{"/tmp/workspace/repo", "/home/runner/work/app", "./relative/clone"}
	for _, p := range allowed {
		if _, err := confineScanPath(p); err != nil {
			t.Errorf("confineScanPath(%q): expected allowed, got %v", p, err)
		}
	}
}

// --- validateScanTarget: per-scanner guard selection ---

// Regression for the SAST/SCA breakage: filesystem scanners (semgrep, trivy
// fs) must NOT be run through the network SSRF/DNS guard — a path is not a
// hostname, so the DNS lookup fails closed and rejected every filesystem scan.
func TestValidateScanTarget_FilesystemScannersAcceptPaths(t *testing.T) {
	cases := []struct{ scanner, target string }{
		{"semgrep", "/tmp/workspace/app"},
		{"semgrep", "."},
		{"trivy", "/tmp/workspace/repo"},
		{"trivy", "./src"},
	}
	for _, c := range cases {
		got, err := validateScanTarget(c.scanner, c.target)
		if err != nil {
			t.Errorf("validateScanTarget(%q, %q): expected allowed, got %v", c.scanner, c.target, err)
		}
		if got == "" {
			t.Errorf("validateScanTarget(%q, %q): expected a confined path, got empty", c.scanner, c.target)
		}
	}
}

// Filesystem scanners still refuse sensitive host paths (path confinement).
func TestValidateScanTarget_FilesystemScannersBlockSensitivePaths(t *testing.T) {
	for _, c := range []struct{ scanner, target string }{
		{"semgrep", "/etc"},
		{"trivy", "/root/.ssh"},
	} {
		if _, err := validateScanTarget(c.scanner, c.target); err == nil {
			t.Errorf("validateScanTarget(%q, %q): sensitive path must be rejected", c.scanner, c.target)
		}
	}
}

// trivy container-image refs are registry coordinates — neither guard applies.
func TestValidateScanTarget_TrivyImageRefsSkipGuards(t *testing.T) {
	for _, target := range []string{"nginx:latest", "ghcr.io/org/app:1.2", "docker:alpine"} {
		got, err := validateScanTarget("trivy", target)
		if err != nil {
			t.Errorf("validateScanTarget(trivy, %q): image ref must pass, got %v", target, err)
		}
		if got != target {
			t.Errorf("validateScanTarget(trivy, %q): image ref must pass through unchanged, got %q", target, got)
		}
	}
}

// Network scanners keep the full SSRF guard: public URLs pass, IMDS is blocked,
// and a bare path (treated as a host) is rejected.
func TestValidateScanTarget_NetworkScannerKeepsSSRFGuard(t *testing.T) {
	if _, err := validateScanTarget("nuclei", "https://example.com"); err != nil {
		t.Errorf("nuclei + public URL must pass, got %v", err)
	}
	if _, err := validateScanTarget("nuclei", "http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("nuclei + IMDS URL must be blocked")
	}
	if _, err := validateScanTarget("nuclei", "/etc/passwd"); err == nil {
		t.Error("nuclei + filesystem path (not a host) must be rejected")
	}
	// An explicit URL scheme is network-guarded regardless of scanner.
	if _, err := validateScanTarget("semgrep", "http://169.254.169.254/"); err == nil {
		t.Error("explicit URL scheme must hit the SSRF guard even for a filesystem scanner")
	}
}
