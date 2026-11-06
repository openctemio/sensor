package webshot

import (
	"net"
	"net/url"
	"strings"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

// requestPolicy decides every request the browser makes, before it leaves
// the browser (the Fetch domain pauses each one). It is the second gate: the
// task's egress forwarder admits only the job's targets whatever the
// browser asks for, and the task's network namespace has no other way out.
//
//   - only http and https (file:, data: subresources, blob:, chrome:,
//     ftp:, ws: and every other scheme is refused; a data: or blob: URL
//     never reaches the network anyway, so refusing it only keeps pages
//     from building content the forwarder never saw);
//   - only GET and HEAD: a page cannot make the browser change state on
//     the target (no form post, no fetch POST, no beacon);
//   - the host must be one of the task's targets, or allowed by the job's
//     web scope when the job carries one;
//   - no user information in the URL, no request to a loopback, link-local
//     or unspecified address literal.
type requestPolicy struct {
	// hosts are the targets' host names (lower case, no port).
	hosts map[string]bool
	// scope is the job's web scope (nil: the hosts only).
	scope *webscope.Scope
	// targets are the target host names, the hosts of a web scope that
	// names none.
	targets []string
	// maxRequests bounds the requests of one page (0: none).
	maxRequests int
}

func newRequestPolicy(targetURLs []*url.URL, scope *webscope.Scope) *requestPolicy {
	p := &requestPolicy{hosts: map[string]bool{}, scope: scope}
	for _, u := range targetURLs {
		h := normHost(u.Hostname())
		if !p.hosts[h] {
			p.hosts[h] = true
			p.targets = append(p.targets, h)
		}
	}
	return p
}

// Refusal reasons (logged per task as counts, never with the URL).
const (
	refuseScheme = "scheme"
	refuseMethod = "method"
	refuseHost   = "host"
	refuseURL    = "url"
	refuseScope  = "web_scope"
	refuseBudget = "budget"
)

// decide returns "" when the request may go, else the refusal reason.
func (p *requestPolicy) decide(method, rawURL string) string {
	if len(rawURL) > maxURLBytes {
		return refuseURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return refuseURL
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return refuseScheme
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
	default:
		return refuseMethod
	}
	if u.User != nil || u.Host == "" {
		return refuseURL
	}
	host := normHost(u.Hostname())
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast()) {
		return refuseHost
	}
	if p.scope != nil {
		if err := p.scope.Allows(strings.ToUpper(method), u, p.targets); err != nil {
			return refuseScope
		}
		return ""
	}
	if !p.hosts[host] {
		return refuseHost
	}
	return ""
}

// maxURLBytes bounds a URL the browser may request.
const maxURLBytes = 8 << 10

// normHost is a host name as compared: lower case, no trailing dot.
func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }
