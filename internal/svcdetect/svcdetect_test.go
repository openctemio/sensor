package svcdetect

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// server is a loopback test server that counts its connections.
type server struct {
	ln    net.Listener
	conns atomic.Int32
}

func serve(t *testing.T, handle func(c net.Conn)) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				handle(c)
			}()
		}
	}()
	return s
}

func (s *server) value() string { return s.ln.Addr().String() + "/tcp" }

func runTool(t *testing.T, cfg Config, identity *tool.Identity, values ...string) *testkit.Result {
	t.Helper()
	local, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	task := tool.Task{Capability: "detect.services@1", Local: local, Identity: identity}
	for i, v := range values {
		task.Targets = append(task.Targets, tool.Target{Ref: fmt.Sprintf("t%d", i), Type: "service", Value: v})
	}
	return testkit.Run(t, Tool, task, testkit.Options{Timeout: 60 * time.Second})
}

func serviceOf(res *testkit.Result, value string) *ctis.ServiceTechnical {
	if res.Report == nil {
		return nil
	}
	for _, a := range res.Report.Assets {
		if a.Type == ctis.AssetTypeService && a.Value == value && a.Technical != nil {
			return a.Technical.Service
		}
	}
	return nil
}

func targetState(res *testkit.Result, ref string) (tool.TargetState, string) {
	for _, o := range res.Targets {
		if o.Ref == ref {
			return o.State, o.Detail
		}
	}
	return "", ""
}

// clean reports what is wrong with a reported string ("" when clean).
func clean(v string, maxLen int) string {
	if len(v) > maxLen {
		return fmt.Sprintf("%d bytes", len(v))
	}
	if !utf8.ValidString(v) {
		return "invalid UTF-8"
	}
	for _, r := range v {
		if isControl(r) {
			return fmt.Sprintf("control character %U", r)
		}
	}
	return ""
}

// lineServer greets with greeting, then answers every line with reply.
func lineServer(greeting, reply string) func(net.Conn) {
	return func(c net.Conn) {
		if _, err := io.WriteString(c, greeting); err != nil {
			return
		}
		br := bufio.NewReader(c)
		for range 16 {
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
			if _, err := io.WriteString(c, reply); err != nil {
				return
			}
		}
	}
}

// hostile is what a hostile server puts in its banner: terminal escapes,
// CR/LF to forge log lines, NUL, invalid UTF-8, markup, bidi overrides.
const hostile = "\x1b]0;owned\x07\x1b[31mRED\x1b[0m\r\nlevel=ERROR msg=forged\x00\xff\xfe<script>alert(1)</script>\u202eevil"

func TestHostileBanners(t *testing.T) {
	// 64 KiB of greeting, read as an FTP banner.
	big := serve(t, lineServer("220 FTP server ready "+hostile+strings.Repeat("A", 64<<10)+"\r\n", ""))
	smtp := serve(t, lineServer("220-mail ESMTP "+hostile+"\r\n220 ready\r\n", "250-mail\r\n250 AUTH PLAIN\r\n"))
	ssh := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-Evil_1.0 "+hostile[:40]+"\r\n")
		_, _ = c.Read(make([]byte, 256))
		_, _ = c.Write([]byte{0, 0, 0, 4, 0}) // not a KEXINIT
	})
	res := runTool(t, Config{}, nil, big.value(), smtp.value(), ssh.value())
	res.RequireStatus(t, tool.StatusOK)
	for value, proto := range map[string]string{big.value(): "ftp", smtp.value(): "smtp"} {
		s := serviceOf(res, value)
		if s == nil || s.AppProtocol != proto {
			t.Fatalf("hostile %s server: %+v", proto, s)
		}
		if s.Banner == "" || !strings.Contains(s.Banner, "<script>") {
			t.Errorf("%s banner %q: want the text kept, cleaned", proto, s.Banner)
		}
		for _, f := range []struct{ name, v string }{{"banner", s.Banner}, {"product", s.Product}, {"version", s.Version}} {
			if p := clean(f.v, MaxBanner); p != "" {
				t.Errorf("%s %s: %s: %q", proto, f.name, p, f.v)
			}
		}
		if len(s.Details) > MaxDetails {
			t.Errorf("%s: %d details", proto, len(s.Details))
		}
		for k, v := range s.Details {
			if p := clean(v, MaxDetailValue); p != "" {
				t.Errorf("%s details[%s]: %s", proto, k, p)
			}
		}
	}
	h := serviceOf(res, ssh.value())
	if h == nil || h.AppProtocol != "ssh" || h.Product != "Evil" || h.Version != "1.0" {
		t.Fatalf("ssh: %+v", h)
	}
	if p := clean(h.Banner, MaxBanner); p != "" || !strings.HasPrefix(h.Banner, "SSH-2.0-Evil_1.0 ") {
		t.Errorf("ssh banner %q: %s", h.Banner, p)
	}
	// No banner reaches a log line.
	for _, l := range res.Logs {
		line := fmt.Sprint(l.Msg, l.Attrs)
		for _, bad := range []string{"owned", "forged", "script", "Evil", "\x1b"} {
			if strings.Contains(line, bad) {
				t.Errorf("log line carries the banner: %q", line)
			}
		}
	}
}

// redisServer answers PING with PONG (no password) and INFO with a version.
func redisServer(c net.Conn) {
	br := bufio.NewReader(c)
	for range 8 {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if !strings.HasPrefix(line, "*") {
			continue
		}
		var n int
		_, _ = fmt.Sscanf(line, "*%d", &n)
		var args []string
		for range n {
			_, _ = br.ReadString('\n')
			a, _ := br.ReadString('\n')
			args = append(args, strings.TrimSpace(a))
		}
		switch strings.ToUpper(args[0]) {
		case "PING":
			_, _ = io.WriteString(c, "+PONG\r\n")
		case "INFO":
			body := "# Server\r\nredis_version:7.2.4\r\n"
			_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(body), body)
		default:
			_, _ = io.WriteString(c, "-ERR unknown\r\n")
		}
	}
}

// A silent server on a port that hints nothing: fast tries TLS and HTTP
// only; thorough finds Redis, reports its version and that PING needed no
// password.
func TestDepth(t *testing.T) {
	srv := serve(t, redisServer)
	res := runTool(t, Config{TimeoutMs: 300}, nil, srv.value())
	if s := serviceOf(res, srv.value()); s != nil {
		t.Fatalf("fast identified %+v on a port that hints nothing", s)
	}
	if st, _ := targetState(res, "t0"); st != tool.StateDone {
		t.Errorf("fast: target %s", st)
	}
	fast := srv.conns.Load()
	if fast > BudgetFast {
		t.Errorf("fast used %d connections", fast)
	}
	res = runTool(t, Config{Depth: DepthThorough, TimeoutMs: 300}, nil, srv.value())
	s := serviceOf(res, srv.value())
	if s == nil || s.AppProtocol != "redis" || s.Version != "7.2.4" || !s.HasAnonymousAccess || s.Product != "redis" {
		t.Fatalf("thorough: %+v", s)
	}
	if s.CPE != "cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*" {
		t.Errorf("cpe %q", s.CPE)
	}
}

// A server that accepts and never answers: the budget bounds the
// connections of one service.
func TestConnectionBudget(t *testing.T) {
	for _, tc := range []struct {
		depth string
		max   int32
	}{{DepthFast, BudgetFast}, {DepthThorough, BudgetThorough}} {
		srv := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
		res := runTool(t, Config{Depth: tc.depth, TimeoutMs: 100}, nil, srv.value())
		res.RequireStatus(t, tool.StatusOK)
		if n := srv.conns.Load(); n < 1 || n > tc.max {
			t.Errorf("%s: %d connections, budget %d", tc.depth, n, tc.max)
		}
	}
}

// Many services of one host: at most HostConcurrency connections at once.
func TestHostConcurrency(t *testing.T) {
	var peak, open atomic.Int32
	orig := dial
	dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := orig(ctx, network, address)
		if err != nil {
			return nil, err
		}
		n := open.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		return &countedConn{Conn: c, open: &open}, nil
	}
	t.Cleanup(func() { dial = orig })
	var values []string
	for range 6 {
		srv := serve(t, func(c net.Conn) {
			time.Sleep(150 * time.Millisecond)
			_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n")
			_, _ = c.Read(make([]byte, 64))
		})
		values = append(values, srv.value())
	}
	res := runTool(t, Config{Rate: 1000}, nil, values...)
	res.RequireStatus(t, tool.StatusOK)
	if p := peak.Load(); p > HostConcurrency || p < 1 {
		t.Fatalf("peak of %d connections to one host", p)
	}
	for _, v := range values {
		if s := serviceOf(res, v); s == nil || s.AppProtocol != "ssh" {
			t.Errorf("%s: %+v", v, s)
		}
	}
}

// countedConn counts itself out of the open connections when closed.
type countedConn struct {
	net.Conn
	open *atomic.Int32
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.open.Add(-1) })
	return c.Conn.Close()
}

// Every connection goes to a target's own address.
func TestDialsOnlyTargets(t *testing.T) {
	a := serve(t, redisServer)
	b := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	var mu sync.Mutex
	var dialed []string
	orig := dial
	dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+address)
		mu.Unlock()
		return orig(ctx, network, address)
	}
	t.Cleanup(func() { dial = orig })
	runTool(t, Config{Depth: DepthThorough, TimeoutMs: 100}, nil, a.value(), b.value())
	allowed := map[string]bool{"tcp " + a.ln.Addr().String(): true, "tcp " + b.ln.Addr().String(): true}
	if len(dialed) == 0 {
		t.Fatal("nothing dialed")
	}
	for _, d := range dialed {
		if !allowed[d] {
			t.Errorf("dialed %s, not a target", d)
		}
	}
}

// On a confined sandbox every connection is a CONNECT through the task's
// forwarder; a refused destination is skipped, never dialed directly.
func TestThroughTheForwarder(t *testing.T) {
	sshSrv := serve(t, lineServer("SSH-2.0-OpenSSH_9.6p1 Debian\r\n", ""))
	var mu sync.Mutex
	var connects []string
	proxy := serve(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		mu.Lock()
		connects = append(connects, req.Host)
		mu.Unlock()
		if req.Host != "203.0.113.7:22" {
			_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
			return
		}
		up, err := net.Dial("tcp", sshSrv.ln.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = up.Close() }()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		go func() { _, _ = io.Copy(up, br) }()
		_, _ = io.Copy(c, up)
	})
	t.Setenv(tool.EnvEgressProxy, "http://"+proxy.ln.Addr().String())
	res := runTool(t, Config{TimeoutMs: 500}, nil, "203.0.113.7:22/tcp", "203.0.113.8:22/tcp")
	if s := serviceOf(res, "203.0.113.7:22/tcp"); s == nil || s.AppProtocol != "ssh" || s.Product != "OpenSSH" || s.Version != "9.6p1" {
		t.Fatalf("through the forwarder: %+v", s)
	}
	if st, detail := targetState(res, "t1"); st != tool.StateSkipped || !strings.Contains(detail, "refused") {
		t.Errorf("refused destination: %s %q", st, detail)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, c := range connects {
		if c != "203.0.113.7:22" && c != "203.0.113.8:22" {
			t.Errorf("CONNECT %s", c)
		}
	}
}

func TestSkippedTargets(t *testing.T) {
	srv := serve(t, lineServer("SSH-2.0-OpenSSH_9.6\r\n", ""))
	_, port, _ := net.SplitHostPort(srv.ln.Addr().String())
	res := runTool(t, Config{Ports: "1-1000"}, nil,
		"127.0.0.1:53/udp", "127.0.0.1:2905/sctp", "10.0.0.0/24", "http://127.0.0.1:"+port+"/", srv.value())
	want := map[string]string{"t0": "opt-in", "t1": "sctp", "t2": "not a service", "t3": "not a service", "t4": "not in the scan's ports"}
	for ref, w := range want {
		if st, d := targetState(res, ref); st != tool.StateSkipped || !strings.Contains(d, w) {
			t.Errorf("%s: %s %q, want skipped %q", ref, st, d, w)
		}
	}
	if srv.conns.Load() != 0 {
		t.Error("a filtered port was probed")
	}
	res = runTool(t, Config{Transports: []string{"tcp", "udp"}}, nil, "127.0.0.1:53/udp")
	if st, d := targetState(res, "t0"); st != tool.StateSkipped || !strings.Contains(d, "no UDP route") {
		t.Errorf("udp opted in: %s %q", st, d)
	}
}

// A plugin that panics on a short answer is a non-match, never a crash.
func TestPluginPanicIsANonMatch(t *testing.T) {
	srv := serve(t, lineServer("@RS", ""))
	res := runTool(t, Config{Depth: DepthThorough, TimeoutMs: 200}, nil, srv.value())
	res.RequireStatus(t, tool.StatusOK)
	if st, _ := targetState(res, "t0"); st != tool.StateDone {
		t.Errorf("target %s", st)
	}
}

// The HTTP probe sends the job's identification and nothing that
// authenticates.
func TestHTTPProbeIdentity(t *testing.T) {
	var got http.Header
	var mu sync.Mutex
	srv := serve(t, func(c net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		mu.Lock()
		got = req.Header.Clone()
		mu.Unlock()
		_, _ = io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	})
	res := runTool(t, Config{}, &tool.Identity{UserAgent: "Acme-Scan/2", Headers: map[string]string{"X-Scan-Id": "42"}}, srv.value())
	s := serviceOf(res, srv.value())
	if s == nil || s.AppProtocol != "http" || s.Banner != "HTTP/1.1 404 Not Found" || s.IsTLS {
		t.Fatalf("http: %+v", s)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Get("User-Agent") != "Acme-Scan/2" || got.Get("X-Scan-Id") != "42" || got.Get("Authorization") != "" || got.Get("Cookie") != "" {
		t.Errorf("headers %v", got)
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"  a\r\n\tb  ":           "a b",
		"\x1b[31mred\x1b[0m":     "[31mred [0m",
		"ok\x00\xff\xfe end":     "ok end",
		"\u202eevil \u2066x":     "evil x",
		"café <b>":               "café <b>",
		strings.Repeat("é", 400): strings.Repeat("é", 256),
	} {
		if got := cleanText(in, MaxBanner); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanText(strings.Repeat("a", 2000), MaxBanner); len(got) != MaxBanner {
		t.Errorf("not cut: %d", len(got))
	}
	d := detailsFrom(map[string]any{"user_password": "x", "Auth-Token": "y", "os": "Linux\r\n", "nested": map[string]any{"a": 1}, "list": []any{"a", "b"}, "n": 3.0})
	if len(d) != 3 || d["os"] != "Linux" || d["list"] != "a, b" || d["n"] != "3" {
		t.Errorf("details %v", d)
	}
}

func TestUsableCPE(t *testing.T) {
	if c, p := usableCPE("cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"); c != "" || p != "redis" {
		t.Errorf("wildcard version kept: %q %q", c, p)
	}
	if c, p := usableCPE("cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*"); c == "" || p != "mysql" {
		t.Errorf("versioned dropped: %q %q", c, p)
	}
	if c, p := usableCPE("not a cpe"); c != "" || p != "" {
		t.Errorf("garbage kept: %q %q", c, p)
	}
}

func TestOwnProbeParsers(t *testing.T) {
	for line, ok := range map[string]bool{"HTTP/1.1 200 OK": true, "HTTP/1.0 404": true, "HTTP/1.1 99 x": false, "HTTP/2 200": false, "RTSP/1.0 200 OK": false, "HTTP/1.1 2000": false} {
		if httpStatusLine(line) != ok {
			t.Errorf("httpStatusLine(%q) != %v", line, ok)
		}
	}
	if !ldapAnswer([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}) {
		t.Error("searchResDone not read")
	}
	if ldapAnswer([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07}) || ldapAnswer([]byte{0x30, 0x84}) || ldapAnswer(nil) {
		t.Error("not a search answer read as one")
	}
	if p, v := sshSoftware("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"); p != "OpenSSH" || v != "9.6p1" {
		t.Errorf("%q %q", p, v)
	}
	if p, v := sshSoftware("SSH-1.99-Cisco-1.25"); p != "Cisco-1.25" || v != "" {
		t.Errorf("%q %q", p, v)
	}
	// A KEXINIT with two name-lists set.
	var payload []byte
	payload = append(payload, 20)
	payload = append(payload, make([]byte, 16)...)
	for _, l := range []string{"curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes256-gcm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "none", "none"} {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(l))) //nolint:gosec // test
		payload = append(payload, l...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	pkt := binary.BigEndian.AppendUint32(nil, uint32(len(payload)+1+4)) //nolint:gosec // test
	pkt = append(pkt, 4)
	pkt = append(pkt, payload...)
	pkt = append(pkt, 0, 0, 0, 0)
	kex, err := readKexInit(bufio.NewReader(strings.NewReader(string(pkt))))
	if err != nil || kex["kex_algorithms"] != "curve25519-sha256" || kex["ciphers_server_to_client"] != "aes256-gcm@openssh.com" || kex["macs_server_to_client"] != "hmac-sha2-512" {
		t.Errorf("kexinit %v %v", kex, err)
	}
	if _, err := readKexInit(bufio.NewReader(strings.NewReader("\xff\xff\xff\xff\x00"))); err == nil {
		t.Error("oversized packet read")
	}
	// PostgreSQL: exactly one S or N byte.
	for answer, ok := range map[string]bool{"N": true, "S": true, "NX": false, "E": false} {
		a, b := net.Pipe()
		go func() {
			buf := make([]byte, 8)
			_, _ = io.ReadFull(b, buf)
			_, _ = io.WriteString(b, answer)
			time.Sleep(200 * time.Millisecond)
			_ = b.Close()
		}()
		r, _ := probePostgres(a, time.Second, &target{})
		if (r != nil) != ok {
			t.Errorf("postgres answer %q: %+v", answer, r)
		}
		_ = a.Close()
	}
}

func TestReadConfig(t *testing.T) {
	cfg := func(c Config) tool.Task {
		b, _ := json.Marshal(c)
		return tool.Task{Local: b}
	}
	s, err := readConfig(cfg(Config{Rate: 5000, TimeoutMs: 1}))
	if err != nil || s.rate != MaxRate || s.timeoutMs != MinTimeoutMs || s.thorough || s.udp {
		t.Errorf("%+v %v", s, err)
	}
	for _, bad := range []Config{{Depth: "deep"}, {Transports: []string{"sctp"}}, {Ports: "0"}, {Ports: "9-1"}, {Ports: "70000"}, {Ports: "a"}} {
		if _, err := readConfig(cfg(bad)); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	p, err := parsePorts("22,80,8000-8100")
	if err != nil || !p.has(22) || !p.has(8050) || p.has(23) {
		t.Errorf("ports %v %v", p, err)
	}
}
