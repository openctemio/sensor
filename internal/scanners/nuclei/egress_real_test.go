//go:build linux

package nuclei

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sensor/internal/toolrun"
)

// connectProxy is an HTTP CONNECT proxy that requires user:pass and
// records each tunnel's destination.
type connectProxy struct {
	mu    sync.Mutex
	dests []string
}

func (p *connectProxy) serve(ln net.Listener, user, pass string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			br := bufio.NewReader(c)
			req, err := http.ReadRequest(br)
			if err != nil || req.Method != http.MethodConnect {
				return
			}
			if req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) {
				_, _ = io.WriteString(c, "HTTP/1.1 407 Auth\r\n\r\n")
				return
			}
			up, err := net.Dial("tcp", req.Host)
			if err != nil {
				_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
				return
			}
			defer func() { _ = up.Close() }()
			p.mu.Lock()
			p.dests = append(p.dests, req.Host)
			p.mu.Unlock()
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			done := make(chan struct{})
			go func() { _, _ = io.Copy(up, br); close(done) }()
			_, _ = io.Copy(c, up)
			_ = c.Close()
			<-done
		}()
	}
}

func (p *connectProxy) tunnels() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.dests...)
}

// hostAddr is an address of this host a proxy endpoint may have (not
// loopback or link-local), or an invalid one.
func hostAddr() netip.Addr {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !upstream.Denied(p.Addr()) {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

// SECURITY (acceptance): the real nuclei binary, run out of process in a
// sandbox that confines its network to the task's forwarder, with the
// job's proxy pool: every request reaches the target through the pool's
// proxy (with the pool's credentials, which nuclei never sees), and none
// goes direct.
func TestRealNucleiThroughThePool(t *testing.T) {
	bin := os.Getenv(EnvRealNuclei)
	if bin == "" {
		t.Skipf("%s is not set", EnvRealNuclei)
	}
	be, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ConfineNetwork: true, RequireNetwork: true,
		Limits: executor.Limits{Processes: 1024}})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment, not available: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
	host := hostAddr()
	if !host.IsValid() {
		t.Skip("no non-loopback address for a test proxy")
	}
	t.Setenv(toolrun.EnvRuntime, "")
	toolrun.SetHost(&toolhost.Host{RuntimeName: "openctem-sensor", Backend: be})
	t.Cleanup(func() { toolrun.SetHost(&toolhost.Host{RuntimeName: "openctem-sensor"}) })

	const user, pass = "nuclei-pool-user", "nuclei-pool-secret-42"
	ln, err := net.Listen("tcp", netip.AddrPortFrom(host, 0).String())
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	defer func() { _ = ln.Close() }()
	proxy := &connectProxy{}
	go proxy.serve(ln, user, pass)

	site := &recordingSite{}
	hs := httptest.NewServer(site)
	defer hs.Close()
	targetAddr := hs.Listener.Addr().String()

	pool, err := upstream.New(upstream.Config{Mode: upstream.ModePool, PoolID: "p1", AppliesTo: upstream.AppliesAll,
		Endpoints: []upstream.Endpoint{{ID: "ep-1", Scheme: upstream.SchemeHTTP, Host: host.String(),
			Port: ln.Addr().(*net.TCPAddr).Port, Weight: 1, Auth: true}}}, upstream.Options{Key: "job-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetCredentials([]upstream.Credential{{EndpointID: "ep-1", Username: user, Password: pass}}); err != nil {
		t.Fatal(err)
	}

	s := NewScanner()
	s.Binary = bin
	res, err := s.Scan(context.Background(), strings.Replace(hs.URL, "127.0.0.1", "localhost", 1),
		&core.ScanOptions{CustomTemplateDir: writeWebScopeTemplates(t), Egress: pool})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !contains(site.served(), "/public/ok") || !strings.Contains(string(res.RawOutput), "ws-allowed") {
		t.Fatalf("the target was not reached through the pool; served %v (%.500s)", site.served(), res.Error)
	}
	tunnels := proxy.tunnels()
	if len(tunnels) == 0 {
		t.Fatal("no request went through the pool's proxy")
	}
	for _, d := range tunnels {
		if d != targetAddr {
			t.Fatalf("a tunnel to %s, not the target's checked address %s", d, targetAddr)
		}
	}
	// Each request the site served came through a tunnel (nuclei may reuse
	// a connection for several requests, never the other way round).
	if len(site.served()) < len(tunnels) {
		t.Fatalf("served %d requests over %d tunnels", len(site.served()), len(tunnels))
	}
	if r := pool.Report(); len(r.Endpoints) != 1 || r.Endpoints[0].OK != int64(len(tunnels)) {
		t.Fatalf("pool report %+v, tunnels %d", r, len(tunnels))
	}
	for _, out := range []string{string(res.RawOutput), res.Error, res.Stderr} {
		if strings.Contains(out, pass) || strings.Contains(out, user) {
			t.Fatal("the pool's credentials reached the tool's output")
		}
	}
}
