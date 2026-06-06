// Package targetguard validates the scan targets a runner is asked to scan
// (RFC-007 §8 R1).
//
// THREAT MODEL: a compromised OpenCTEM control plane weaponizing the runner to
// scan sensitive infrastructure. The runner is the only component that can reach
// the appliance + the internal network, so it must NOT blindly trust dispatched
// targets. This guard is the runner's independent check: it blocks ranges that
// are never a legitimate scan target (cloud metadata, loopback, link-local) and
// bounds how much a single job may scan, regardless of what the control plane
// asked for.
//
// IMPORTANT — this is NOT an SSRF guard. An SSRF guard blocks RFC1918; a vuln
// scanner's entire purpose is to scan the internal corporate network, so private
// ranges are ALLOWED here. Only the dangerous, never-legitimate ranges are
// blocked.
package targetguard

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// Defaults for the size bounds. They cap blast radius if a (possibly
// compromised) control plane dispatches an enormous target set.
const (
	// DefaultMaxHostsPerTarget bounds a single CIDR target (a /16). A request to
	// scan something larger (e.g. /8 or 0.0.0.0/0) is refused.
	DefaultMaxHostsPerTarget = 1 << 16
	// DefaultMaxTargets bounds how many targets one job may carry.
	DefaultMaxTargets = 4096
)

// hardBlockedRanges are never legitimate scan targets and are blocked regardless
// of configuration:
//   - 127.0.0.0/8, ::1/128: loopback — would scan the runner host itself.
//   - 169.254.0.0/16, fe80::/10: link-local, incl. cloud metadata
//     (169.254.169.254) — leaks IAM credentials.
//   - 100.64.0.0/10: carrier-grade NAT, never a tenant network.
//   - 0.0.0.0/8, ::/128: "this"/unspecified.
//   - 224.0.0.0/4, ff00::/8: multicast.
//   - 240.0.0.0/4, 255.255.255.255/32: reserved / broadcast.
var hardBlockedRanges = []string{
	"127.0.0.0/8",
	"169.254.0.0/16",
	"100.64.0.0/10",
	"0.0.0.0/8",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::1/128",
	"::/128",
	"fe80::/10",
	"ff00::/8",
}

// dangerousHosts are string-level aliases that resolve to metadata/local
// services; blocked before DNS resolution.
var dangerousHosts = map[string]struct{}{
	"localhost":                {},
	"metadata":                 {},
	"metadata.google.internal": {},
	"metadata.google":          {},
	"169.254.169.254":          {},
}

// Guard validates scan targets against the blocklist + size bounds.
type Guard struct {
	blocked           []*net.IPNet
	maxHostsPerTarget int
	maxTargets        int
	resolver          *net.Resolver
}

// New builds a Guard. Non-positive bounds fall back to the package defaults.
func New(maxHostsPerTarget, maxTargets int) *Guard {
	if maxHostsPerTarget <= 0 {
		maxHostsPerTarget = DefaultMaxHostsPerTarget
	}
	if maxTargets <= 0 {
		maxTargets = DefaultMaxTargets
	}
	blocked := make([]*net.IPNet, 0, len(hardBlockedRanges))
	for _, cidr := range hardBlockedRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			blocked = append(blocked, ipNet)
		}
	}
	return &Guard{
		blocked:           blocked,
		maxHostsPerTarget: maxHostsPerTarget,
		maxTargets:        maxTargets,
		resolver:          net.DefaultResolver,
	}
}

// ValidateTargets checks every target and fails the WHOLE set if any target is
// blocked or out of bounds. Fail-loud is deliberate: against a compromised
// control plane we want a hard, auditable stop, not a silent partial scan.
func (g *Guard) ValidateTargets(ctx context.Context, targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets")
	}
	if len(targets) > g.maxTargets {
		return fmt.Errorf("too many targets: %d (max %d)", len(targets), g.maxTargets)
	}
	for _, t := range targets {
		if err := g.validateTarget(ctx, t); err != nil {
			return fmt.Errorf("target %q rejected: %w", t, err)
		}
	}
	return nil
}

func (g *Guard) validateTarget(ctx context.Context, target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("empty target")
	}

	// CIDR: bound the size, then reject if it overlaps any blocked range.
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		if n := hostCount(ipNet); n.Cmp(big.NewInt(int64(g.maxHostsPerTarget))) > 0 {
			return fmt.Errorf("range too large: %s hosts (max %d)", n.String(), g.maxHostsPerTarget)
		}
		for _, b := range g.blocked {
			if cidrsOverlap(ipNet, b) {
				return fmt.Errorf("overlaps blocked range %s", b.String())
			}
		}
		return nil
	}

	// Bare host: a literal IP, or a hostname to resolve.
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	lower := strings.ToLower(host)
	if _, bad := dangerousHosts[lower]; bad {
		return fmt.Errorf("blocked host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if g.isBlockedIP(ip) {
			return fmt.Errorf("blocked address")
		}
		return nil
	}

	// Hostname → resolve and check every A/AAAA. Fail-closed on DNS failure: if
	// we cannot resolve it we cannot prove it is safe.
	ips, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("dns resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no addresses resolved")
	}
	for _, ip := range ips {
		if g.isBlockedIP(ip.IP) {
			return fmt.Errorf("resolves to blocked address %s", ip.IP)
		}
	}
	return nil
}

func (g *Guard) isBlockedIP(ip net.IP) bool {
	for _, b := range g.blocked {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

// cidrsOverlap reports whether two CIDRs intersect.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// hostCount returns the number of addresses in a CIDR as a big.Int (IPv6 blocks
// can exceed int64).
func hostCount(ipNet *net.IPNet) *big.Int {
	ones, bits := ipNet.Mask.Size()
	return new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
}
