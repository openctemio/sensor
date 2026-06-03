package executor

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// sensitiveScanRoots are absolute directories the agent must never scan as a
// filesystem target, regardless of what a job payload requests. Scanning them
// would let a malicious or compromised job source exfiltrate host secrets
// (e.g. /etc/shadow, SSH/cloud keys) back through findings.
var sensitiveScanRoots = []string{
	"/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/run",
	"/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/lib", "/var/run",
}

// confineScanPath validates a filesystem scan target. It rejects the filesystem
// root and any path resolving to (or inside) a sensitive system directory or a
// well-known secrets dir under the user's home. Returns the cleaned absolute
// path on success. This is defense-in-depth — the agent only scans what the
// platform dispatches, but it must not be coercible into reading host secrets.
func confineScanPath(target string) (string, error) {
	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("scan target is required")
	}
	abs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return "", fmt.Errorf("invalid scan target: %w", err)
	}
	if abs == "/" {
		return "", fmt.Errorf("refusing to scan filesystem root")
	}
	isUnder := func(root string) bool {
		return abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator))
	}
	for _, root := range sensitiveScanRoots {
		if isUnder(root) {
			return "", fmt.Errorf("refusing to scan sensitive system path: %s", abs)
		}
	}
	if home, herr := os.UserHomeDir(); herr == nil && home != "" {
		for _, d := range []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gcloud"} {
			if isUnder(filepath.Join(home, d)) {
				return "", fmt.Errorf("refusing to scan sensitive path: %s", abs)
			}
		}
	}
	return abs, nil
}

// SSRF guard for scanner targets.
//
// Agent-local equivalent of api/pkg/httpsec. Uses a two-tier
// blocklist so an on-prem CTEM deployment (scanning its own
// corporate network) can still operate while cloud-hosted agents
// keep the stricter default.
//
// Threat model: a tenant-admin (or compromised scope-admin) creates
// an asset whose `target` is attacker-controlled. Without this guard,
// the agent hands the URL straight to nuclei `-u`; if the URL points
// at the cloud-metadata endpoint (http://169.254.169.254), the
// response body (containing IAM credentials) lands in a finding
// visible through the UI.
//
// Two-tier design:
//
//   1. hardBlockedTargetCIDRs  — NEVER scannable. Cloud IMDS,
//      loopback on the agent host, CGNAT, multicast, broadcast.
//      No env var opens these.
//
//   2. privateTargetCIDRs      — blocked by DEFAULT; opened by
//      setting AGENT_ALLOW_PRIVATE_TARGETS=1. This is the opt-in
//      for on-prem deployments that legitimately scan their own
//      RFC1918 / ULA space (10.0.0.0/8, 192.168.x.y, 172.16/12,
//      fc00::/7). Operators who run the agent inside their
//      corporate network to audit internal assets should set this
//      at deployment time (Helm values / Docker env) — cloud-only
//      deployments leave it off.
//
// Regardless of the opt-in, IMDS and loopback stay blocked. An
// attacker who flips AGENT_ALLOW_PRIVATE_TARGETS=1 still cannot
// scan 169.254.169.254 — cloud-credential leak is not on the table.

var hardBlockedTargetCIDRs = []string{
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link-local (incl. AWS/GCP/Azure IMDS)
	"100.64.0.0/10",      // Carrier-grade NAT
	"0.0.0.0/8",          // "This" network
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Broadcast
	"::1/128",            // IPv6 loopback
	"fe80::/10",          // IPv6 link-local
}

var privateTargetCIDRs = []string{
	"10.0.0.0/8",     // RFC1918 class A
	"172.16.0.0/12",  // RFC1918 class B
	"192.168.0.0/16", // RFC1918 class C
	"fc00::/7",       // IPv6 ULA
}

// allowPrivateTargets is toggled from the AGENT_ALLOW_PRIVATE_TARGETS
// env var at init-time. Tests override this variable directly to
// exercise both modes. Log at startup so ops can see which posture
// the agent booted with.
var allowPrivateTargets = os.Getenv("AGENT_ALLOW_PRIVATE_TARGETS") == "1"

// AllowPrivateTargets reports the current runtime posture. Called
// by the main binary at startup so the log line makes the deployment
// mode explicit.
func AllowPrivateTargets() bool { return allowPrivateTargets }

// blockedTargetHosts is a string-level allowlist-rejection for
// aliases that hit metadata/local services before DNS resolves.
// These stay blocked regardless of allowPrivateTargets — localhost
// + IMDS aliases are never legit scan targets.
var blockedTargetHosts = []string{
	"localhost",
	"metadata",
	"metadata.google.internal",
	"169.254.169.254",
}

var compiledHardBlockedCIDRs []*net.IPNet
var compiledPrivateCIDRs []*net.IPNet

func init() {
	for _, cidr := range hardBlockedTargetCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			compiledHardBlockedCIDRs = append(compiledHardBlockedCIDRs, n)
		}
	}
	for _, cidr := range privateTargetCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			compiledPrivateCIDRs = append(compiledPrivateCIDRs, n)
		}
	}
}

func isBlockedIP(ip net.IP) bool {
	for _, n := range compiledHardBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	if !allowPrivateTargets {
		for _, n := range compiledPrivateCIDRs {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// validateScannerTarget rejects a scanner target string when it points
// at the loopback / private / link-local / CGNAT / multicast space.
// Returns nil for empty input — callers are responsible for whether an
// empty target is meaningful (some scanners run on a list, not a `-u`).
//
// Accepts both bare host (e.g. "example.com", "1.2.3.4") and full URL
// (e.g. "https://example.com/x"). Bare IPs are checked directly; bare
// hostnames are resolved and every A/AAAA record is checked. DNS
// failure is treated as "do not scan" (fail closed) — without DNS we
// can't prove the target is safe, and a rebinding attack would happily
// resolve at scan time.
//
// Schemes other than http/https are rejected because the dangerous
// `gopher://`, `file://`, `dict://` schemes can also reach internal
// services even when bound to public-IP DNS (libcurl's history).
func validateScannerTarget(target string) error {
	if target == "" {
		return nil
	}

	host := target
	// If it parses as a URL with a scheme, validate scheme + extract host.
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("scanner target is not a valid URL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("scanner target scheme %q is not allowed (only http/https)", u.Scheme)
		}
		host = u.Hostname()
	}
	if host == "" {
		return fmt.Errorf("scanner target has no host")
	}

	hostLower := strings.ToLower(host)
	for _, blocked := range blockedTargetHosts {
		if hostLower == blocked {
			return fmt.Errorf("scanner target host %q is blocked", host)
		}
	}

	// Bare IP literal: check directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("scanner target IP %s falls in a blocked CIDR", ip)
		}
		return nil
	}

	// Hostname: resolve and reject if any record hits a blocked CIDR.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for scanner target %q: %w", host, err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("scanner target %q resolves to blocked address %s", host, ip)
		}
	}
	return nil
}

// validateScannerTargets returns the first error encountered when
// validating each entry in the slice; safe to call with an empty
// slice. Used for batch-target scanners (subfinder, nuclei -l, etc.)
// before the list is materialised on disk.
func validateScannerTargets(targets []string) error {
	for _, t := range targets {
		if err := validateScannerTarget(t); err != nil {
			return err
		}
	}
	return nil
}
