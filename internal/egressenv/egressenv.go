// Package egressenv tells a tool wrapper how a confined task reaches the
// network (api RFC-060): through its forwarder, whose relay the sandbox
// names in OPENCTEM_EGRESS_PROXY (sdk-go executor.EnvEgressProxy). A tool
// that honours HTTP_PROXY and HTTPS_PROXY needs nothing; a tool that takes
// a proxy flag, or its own resolvers, is pointed at the relay here.
package egressenv

import (
	"net"
	"net/url"
	"os"
	"strings"
)

// EnvProxy is the variable the sandbox sets for a confined task with a
// forwarder.
const EnvProxy = "OPENCTEM_EGRESS_PROXY"

// Proxy is the relay's proxy URL ("http://127.0.0.1:1080"), or "" when the
// task is not confined.
func Proxy() string { return strings.TrimSpace(os.Getenv(EnvProxy)) }

// Confined reports whether the task runs confined with a forwarder.
func Confined() bool { return Proxy() != "" }

// SOCKSAddr is the relay as host:port for a tool that takes a SOCKS5
// address (the relay speaks HTTP CONNECT and SOCKS5 on one port), or "".
func SOCKSAddr() string {
	p := Proxy()
	if p == "" {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// Resolver is the relay's DNS address for a tool that takes its own
// resolvers ("127.0.0.1"), or "" when the task is not confined: a
// confined task reaches no other resolver.
func Resolver() string {
	if !Confined() {
		return ""
	}
	host, _, err := net.SplitHostPort(SOCKSAddr())
	if err != nil {
		return "127.0.0.1"
	}
	return host
}
