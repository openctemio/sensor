package executor

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// SSRF guard for scanner targets.
//
// This is the agent-local equivalent of api/pkg/httpsec.ValidateURL.
// Agent does NOT depend on the api module (only sdk-go) so we cannot
// import that package directly. Follow-up: lift the SSRF helper into
// sdk-go so both api and agent share one canonical blocklist.
//
// The threat model: a tenant-admin (or compromised scope-admin) creates
// an asset whose `target` is `http://169.254.169.254/…` and triggers a
// scan. Without this gate, the agent passes the URL straight to nuclei
// `-u`, the cloud-metadata endpoint replies with IAM credentials, and
// the credentials land verbatim in a finding's body — visible in the
// UI and exfiltrated.
//
// Keep CIDR list in sync with api/pkg/httpsec/ssrf.go blockedIPRanges.

var blockedTargetCIDRs = []string{
	"127.0.0.0/8",        // Loopback
	"10.0.0.0/8",         // Private class A
	"172.16.0.0/12",      // Private class B
	"192.168.0.0/16",     // Private class C
	"169.254.0.0/16",     // Link-local (incl. AWS/GCP/Azure IMDS)
	"100.64.0.0/10",      // Carrier-grade NAT
	"0.0.0.0/8",          // "This" network
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Broadcast
	"::1/128",            // IPv6 loopback
	"fc00::/7",           // IPv6 unique-local
	"fe80::/10",          // IPv6 link-local
}

var blockedTargetHosts = []string{
	"localhost",
	"metadata",
	"metadata.google.internal",
	"169.254.169.254",
}

var compiledBlockedCIDRs []*net.IPNet

func init() {
	for _, cidr := range blockedTargetCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			compiledBlockedCIDRs = append(compiledBlockedCIDRs, n)
		}
	}
}

func isBlockedIP(ip net.IP) bool {
	for _, n := range compiledBlockedCIDRs {
		if n.Contains(ip) {
			return true
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
