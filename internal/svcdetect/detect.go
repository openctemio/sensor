package svcdetect

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// probe is one protocol probe: an allowed nerva plugin or one of ours.
type probe struct {
	// name is the application protocol it reports (lower case).
	name string
	// tls: the probe runs over a TLS connection.
	tls bool
	// talksFirst: the probe needs the server's first bytes.
	talksFirst bool
	priority   int
	// portHint: the port is one of the protocol's usual ports.
	portHint func(uint16) bool
	// fallback: in fast depth, also tried on a silent server whose port
	// hints nothing (the HTTP probe).
	fallback bool
	// hintOnly: tried only on its usual ports, in every depth (a probe
	// whose answer is too short to tell apart elsewhere).
	hintOnly bool
	run      func(c net.Conn, timeout time.Duration, t *target) (*result, error)
}

// result is what a probe identified.
type result struct {
	protocol  string
	product   string
	version   string
	cpe       string
	banner    string
	tls       bool
	anonymous bool
	details   map[string]string
}

// target is one service of the task.
type target struct {
	t     tool.Target
	host  string // as in the value, without brackets
	ip    netip.Addr
	port  uint16
	addr  string // host:port, the only address the tool dials for it
	value string // canonical CTIS value
}

func (t *target) addrOrZero() netip.Addr {
	if t.ip.IsValid() {
		return t.ip
	}
	return netip.IPv4Unspecified()
}

// name is the host name ("" for an address).
func (t *target) name() string {
	if t.ip.IsValid() {
		return ""
	}
	return t.host
}

// hostHeader is the Host header of the HTTP probe (the port dropped when it
// is the scheme's default).
func (t *target) hostHeader(useTLS bool) string {
	h := t.host
	if t.ip.Is6() {
		h = "[" + h + "]"
	}
	if (useTLS && t.port == 443) || (!useTLS && t.port == 80) {
		return h
	}
	return h + ":" + strconv.Itoa(int(t.port))
}

// errBudget: the service's connection budget is spent.
var errBudget = errors.New("svcdetect: connection budget of the service spent")

// dialFunc opens a connection; tool.Dial goes through the task's forwarder
// on a confined sandbox.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// detector probes one service.
type detector struct {
	dial     dialFunc
	probes   []*probe
	timeout  time.Duration
	thorough bool
	budget   int
}

// session is the state of one service's probing.
type session struct {
	d     *detector
	ctx   context.Context
	t     *target
	conns int
}

// hardFor is the hard deadline of one connection: a connect, a TLS
// handshake and a few exchanges.
func (d *detector) hardFor() time.Time { return time.Now().Add(4 * d.timeout) }

// connect opens one connection to the target's own address, counted
// against the budget. The address is fixed per target: a probe never
// chooses where to connect.
func (s *session) connect() (*boundedConn, error) {
	if s.conns >= s.d.budget {
		return nil, errBudget
	}
	s.conns++
	ctx, cancel := context.WithTimeout(s.ctx, s.d.timeout)
	defer cancel()
	c, err := s.d.dial(ctx, "tcp", s.t.addr)
	if err != nil {
		return nil, err
	}
	return bound(c, s.d.hardFor(), nil), nil
}

// tlsClient runs a TLS handshake on c. The certificate is not verified:
// detection needs the protocol, not trust (no data or credential is sent).
func (s *session) tlsClient(c net.Conn) (*tls.Conn, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // detection only: no credential or data is sent over it
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS10, //nolint:gosec // legacy servers must still be identified
	}
	if n := s.t.name(); n != "" {
		cfg.ServerName = n
	}
	tc := tls.Client(c, cfg)
	_ = c.SetDeadline(time.Now().Add(s.d.timeout))
	err := tc.HandshakeContext(s.ctx)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	return tc, nil
}

// detect probes one service. It returns nil when nothing was identified,
// and an error only when the service could not be reached at all.
func (d *detector) detect(ctx context.Context, t *target) (*result, error) {
	s := &session{d: d, ctx: ctx, t: t}
	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	wait := d.timeout
	first := c.preRead(wait)
	if len(first) > 0 {
		c.prefix = first
		r := s.lane(c, false, first)
		return withBanner(r, first), nil
	}
	if ctx.Err() != nil {
		_ = c.Close()
		return nil, ctx.Err()
	}
	// A silent server: a TLS handshake on the same connection (nothing was
	// sent on it yet).
	if tc, err := s.tlsClient(c); err == nil {
		if alpn := tc.ConnectionState().NegotiatedProtocol; alpn == "h2" || alpn == "http/1.1" {
			_ = tc.Close()
			return &result{protocol: "https", tls: true, details: map[string]string{"alpn": alpn}}, nil
		}
		tb := bound(tc, d.hardFor(), nil)
		first := tb.preRead(wait)
		tb.prefix = first
		r := s.lane(tb, true, first)
		if r != nil {
			r.tls = true
		}
		return withBanner(r, first), nil
	}
	_ = c.Close()
	return s.lane(nil, false, nil), nil
}

// withBanner sets the server's first bytes as the banner when the probe
// gave none.
func withBanner(r *result, first []byte) *result {
	if r != nil && r.banner == "" && len(first) > 0 {
		r.banner = cleanText(string(first), MaxBanner)
	}
	return r
}

// lane runs the probes that fit what the server did (talked first or not,
// TLS or not) in order, until one identifies the service or the budget is
// spent. c, when set, is a fresh connection for the first probe.
func (s *session) lane(c net.Conn, overTLS bool, first []byte) *result {
	for _, p := range s.d.order(s.t.port, overTLS, first) {
		if s.ctx.Err() != nil {
			break
		}
		conn := c
		c = nil
		if conn == nil {
			var err error
			if conn, err = s.fresh(overTLS); err != nil {
				break
			}
		}
		r, _ := p.run(conn, s.d.timeout, s.t)
		_ = conn.Close()
		if r != nil && r.protocol != "" {
			return r
		}
	}
	if c != nil {
		_ = c.Close()
	}
	return nil
}

// fresh opens a new connection for a probe (with a TLS handshake for a TLS
// lane) and replays nothing: the server greets again.
func (s *session) fresh(overTLS bool) (net.Conn, error) {
	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	if !overTLS {
		return c, nil
	}
	tc, err := s.tlsClient(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return bound(tc, s.d.hardFor(), nil), nil
}

// order is the probes of a lane in the order they run:
//   - a server that talked first: the probes its first bytes hint at, then
//     those of the port's usual protocols, then (thorough) every other
//     talk-first probe;
//   - a silent server: the probes of the port's usual protocols, then the
//     fallbacks (HTTP), then (thorough) every other probe that sends first.
func (d *detector) order(port uint16, overTLS bool, first []byte) []*probe {
	talked := len(first) > 0
	var lane []*probe
	for _, p := range d.probes {
		if p.tls == overTLS && p.talksFirst == talked {
			lane = append(lane, p)
		}
	}
	var out []*probe
	add := func(p *probe) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, h := range bannerHints(first) {
		for _, p := range lane {
			if p.name == h || (overTLS && p.name == h+"s") {
				add(p)
			}
		}
	}
	for _, p := range lane {
		if p.portHint != nil && p.portHint(port) {
			add(p)
		}
	}
	if !talked {
		for _, p := range lane {
			if p.fallback {
				add(p)
			}
		}
	}
	if d.thorough {
		for _, p := range lane {
			if !p.hintOnly {
				add(p)
			}
		}
	}
	return out
}
