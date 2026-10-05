// Package resolv picks the DNS resolvers the recon tools use: the sensor's
// own, never the tools' built-in public resolver lists.
//
// dnsx, naabu and subfinder resolve through hard-coded public resolvers
// (Cloudflare, Google, Quad9, …) unless given -r. That sent every name a
// tenant enumerates to third-party resolvers, and names only the sensor's
// network knows (an internal or split-horizon zone, a Docker or Kubernetes
// service) did not resolve at all: dnsx then reported "completed, 0
// records" (openctemio/openctem research/22c B5). The sensor's resolvers
// are SENSOR_DNS_RESOLVERS when the operator sets it, else the nameservers
// of /etc/resolv.conf, the ones httpx, katana and nuclei already use.
package resolv

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// EnvResolvers is the operator's resolver list: comma-separated IP
// addresses, each optionally with a port (192.0.2.53, 192.0.2.53:5353,
// [2001:db8::53]:53).
const EnvResolvers = "SENSOR_DNS_RESOLVERS"

const (
	// MaxSystem is how many resolv.conf nameservers are used (the libc
	// resolver uses at most three as well).
	MaxSystem = 3
	// MaxEnv bounds SENSOR_DNS_RESOLVERS.
	MaxEnv = 16
	// maxResolvConfBytes bounds the resolv.conf read.
	maxResolvConfBytes = 64 << 10
)

// ResolvConfPath is the resolver configuration read (a var for tests).
var ResolvConfPath = "/etc/resolv.conf"

// System returns the nameserver addresses of a resolv.conf file: IP
// literals only (IPv6 as [addr]:53), deduplicated, at most MaxSystem. An
// unreadable file yields none.
func System(path string) []string {
	f, err := os.Open(path) //nolint:gosec // a fixed system path (a var only for tests)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(io.LimitReader(f, maxResolvConfBytes))
	for sc.Scan() && len(out) < MaxSystem {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil || ip.IsUnspecified() {
			continue // a zone-scoped or malformed entry
		}
		addr := ip.String()
		if ip.To4() == nil {
			addr = net.JoinHostPort(addr, "53")
		}
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// Parse validates a SENSOR_DNS_RESOLVERS value. Only IP addresses are
// accepted: a host name would need a resolver to find the resolver, and a
// value can never become a second flag or a file path.
func Parse(v string) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(v, ",") {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		addr, err := parseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvResolvers, err)
		}
		out = append(out, addr)
		if len(out) > MaxEnv {
			return nil, fmt.Errorf("%s: more than %d resolvers", EnvResolvers, MaxEnv)
		}
	}
	return out, nil
}

func parseAddr(e string) (string, error) {
	if ip := net.ParseIP(e); ip != nil {
		if ip.IsUnspecified() {
			return "", fmt.Errorf("%q is not a resolver address", e)
		}
		if ip.To4() == nil {
			return net.JoinHostPort(ip.String(), "53"), nil
		}
		return ip.String(), nil
	}
	host, port, err := net.SplitHostPort(e)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address or IP:port", e)
	}
	ip := net.ParseIP(host)
	n, perr := strconv.Atoi(port)
	if ip == nil || ip.IsUnspecified() || perr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q is not an IP address or IP:port", e)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n)), nil
}

// Sensor returns the resolvers the recon tools use: SENSOR_DNS_RESOLVERS
// when set (an invalid value is an error, never ignored), else the
// nameservers of ResolvConfPath. None (no list and no readable resolv.conf)
// leaves the tools on their defaults.
func Sensor(lookupEnv func(string) (string, bool)) ([]string, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if v, ok := lookupEnv(EnvResolvers); ok && strings.TrimSpace(v) != "" {
		return Parse(v)
	}
	return System(ResolvConfPath), nil
}
