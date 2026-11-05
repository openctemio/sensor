package webshot

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// The test binary is the sandbox launcher and the tool child too, as the
// sensor binary is.
func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	adapter.Dispatch(Tool)
	os.Exit(m.Run())
}

// outsideAddr is an address of this host that is not loopback (the task's
// forwarder dials it from outside the task's network namespace).
func outsideAddr(t *testing.T) string {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback address")
	return ""
}

// SECURITY: the whole production path: the sensor's scanner runs the tool
// out of process in the browser sandbox (confined network, nested user
// namespace, required mode), Chromium's own sandbox on, through the real
// egress forwarder. The page is captured; the forwarder is the only way
// out, so nothing but the target is ever contacted.
func TestRealBrowserInTheSandbox(t *testing.T) {
	bin := realBrowser(t)
	b, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ConfineNetwork: true,
		RequireNetwork: true, WorkRoot: t.TempDir()})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
	prev := executor.Current()
	executor.SetCurrent(b)
	t.Cleanup(func() { executor.SetCurrent(prev) })
	t.Setenv(core.EnvSensorAllowPrivateTargets, "1")
	t.Setenv(sensorkit.EnvSandbox, "required")
	t.Setenv(sensorkit.EnvSandboxNetwork, "required")

	ip := outsideAddr(t)
	var (
		mu        sync.Mutex
		seenHosts []string
	)
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenHosts = append(seenHosts, r.Method+" "+r.Host+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Sandboxed</title><h1>inside</h1><img src="http://evil.test/x.png">` +
			`<script>fetch("/api",{method:"POST"}).catch(()=>{})</script>`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	s := &Scanner{Browser: bin}
	if ok, _, err := s.IsInstalled(context.Background()); !ok {
		t.Fatalf("not installed in a full sandbox: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := "http://" + ln.Addr().String()
	res, err := s.ScanTargets(ctx, []string{target}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Assets []struct {
			Value      string         `json:"value"`
			Properties map[string]any `json:"properties"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(res.RawOutput, &doc); err != nil || len(doc.Assets) != 1 {
		t.Fatalf("report %s (%v)", res.RawOutput, err)
	}
	list, _ := doc.Assets[0].Properties[PropertyKey].([]any)
	if len(list) != 1 {
		t.Fatalf("evidence %v", doc.Assets[0].Properties)
	}
	ev := list[0].(map[string]any)
	if ev["title"] != "Sandboxed" || ev["screenshot"] == nil {
		t.Fatalf("evidence title %v, screenshot %v", ev["title"], ev["screenshot"] != nil)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, h := range seenHosts {
		if !strings.HasPrefix(h, "GET "+ln.Addr().String()+"/") {
			t.Errorf("the target saw %s", h)
		}
	}
}
