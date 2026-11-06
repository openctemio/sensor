package webshot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"math/rand"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// SECURITY: the page policy lets a request go only over http(s), with GET or
// HEAD, to a target host (or the job's web scope); everything else a hostile
// page asks for is refused before it leaves the browser.
func TestRequestPolicy(t *testing.T) {
	p := newRequestPolicy([]*url.URL{mustURL(t, "https://App.Example.com./")}, nil)
	cases := []struct {
		method, url, want string
	}{
		{"GET", "https://app.example.com/", ""},
		{"HEAD", "https://app.example.com/a.css", ""},
		{"GET", "http://app.example.com:8080/x", ""},
		{"POST", "https://app.example.com/login", refuseMethod},
		{"PUT", "https://app.example.com/", refuseMethod},
		{"OPTIONS", "https://app.example.com/", refuseMethod},
		{"GET", "https://cdn.other.test/lib.js", refuseHost},
		{"GET", "https://evil.example.com.attacker.test/", refuseHost},
		{"GET", "file:///etc/passwd", refuseScheme},
		{"GET", "chrome://settings", refuseScheme},
		{"GET", "ws://app.example.com/socket", refuseScheme},
		{"GET", "ftp://app.example.com/", refuseScheme},
		{"GET", "data:text/html,hi", refuseScheme},
		{"GET", "https://user:pw@app.example.com/", refuseURL},
		{"GET", "http://127.0.0.1:1080/", refuseHost},
		{"GET", "http://[::1]/", refuseHost},
		{"GET", "http://169.254.169.254/latest/meta-data", refuseHost},
		{"GET", "https://app.example.com/" + strings.Repeat("a", maxURLBytes), refuseURL},
	}
	for _, c := range cases {
		if got := p.decide(c.method, c.url); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.method, c.url, got, c.want)
		}
	}
}

// With a web scope the job's hosts, prefixes and deny paths decide, and the
// method stays GET or HEAD whatever the scope allows.
func TestRequestPolicyWebScope(t *testing.T) {
	sc := &webscope.Scope{Hosts: []string{"*.example.com"}, DenyPaths: []string{"/logout"}, Methods: []string{"GET", "POST"}}
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
	p := newRequestPolicy([]*url.URL{mustURL(t, "https://app.example.com/")}, sc)
	for u, want := range map[string]string{
		"https://static.example.com/a.js": "",
		"https://app.example.com/logout":  refuseScope,
		"https://app.example.com/Logout/": refuseScope,
		"https://other.test/":             refuseScope,
	} {
		if got := p.decide("GET", u); got != want {
			t.Errorf("GET %s: %q, want %q", u, got, want)
		}
	}
	if got := p.decide("POST", "https://app.example.com/form"); got != refuseMethod {
		t.Errorf("POST allowed by a scope: %q", got)
	}
}

// The job's identification replaces what the page set for the same header.
func TestWithIdentity(t *testing.T) {
	got := withIdentity(map[string]string{"User-Agent": "page", "x-program": "spoof", "Accept": "*/*"},
		"org-agent", map[string]string{"X-Program": "bb-123"})
	m := map[string]string{}
	for _, h := range got {
		if _, dup := m[strings.ToLower(h["name"])]; dup {
			t.Fatalf("duplicate header %s in %v", h["name"], got)
		}
		m[strings.ToLower(h["name"])] = h["value"]
	}
	if m["user-agent"] != "org-agent" || m["x-program"] != "bb-123" || m["accept"] != "*/*" {
		t.Fatalf("headers %v", m)
	}
}

func pngOf(t *testing.T, w, h int, noise bool) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	r := rand.New(rand.NewSource(1))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{uint8(x), uint8(y), 80, 255}
			if noise {
				c = color.RGBA{uint8(r.Intn(256)), uint8(r.Intn(256)), uint8(r.Intn(256)), 255}
			}
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// SECURITY: only fresh pixels leave the task: a trailer appended to the PNG
// (a polyglot) and its text chunks do not survive; the size cap holds (JPEG
// when the PNG is too large); oversized or non-PNG input is refused.
func TestReencode(t *testing.T) {
	raw := pngOf(t, 64, 48, false)
	// A tEXt chunk is not kept: image/png ignores ancillary chunks.
	hostile := append(append([]byte{}, raw...), []byte("<script>alert(1)</script>PK\x03\x04")...)
	e, err := reencode(hostile, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if e.MediaType != "image/png" || bytes.Contains(e.Data, []byte("<script>")) || bytes.Contains(e.Data, []byte("PK\x03\x04")) {
		t.Fatalf("trailer survived or wrong type %s", e.MediaType)
	}
	if e.Width != 64 || e.Height != 48 {
		t.Fatalf("dims %dx%d", e.Width, e.Height)
	}

	noisy := pngOf(t, 400, 300, true)
	e, err = reencode(noisy, 200<<10)
	if err != nil {
		t.Fatal(err)
	}
	if e.MediaType != "image/jpeg" || len(e.Data) > 200<<10 || !bytes.HasPrefix(e.Data, []byte{0xFF, 0xD8, 0xFF}) {
		t.Fatalf("over the cap: %s %d bytes", e.MediaType, len(e.Data))
	}
	if _, err := reencode(noisy, 1<<10); err == nil {
		t.Fatal("an image over the cap at every quality was accepted")
	}
	if _, err := reencode(pngOf(t, maxImageWidth+1, 2, false), 0); err == nil {
		t.Fatal("an image wider than the platform keeps was accepted")
	}
	if _, err := reencode([]byte("GIF89a...."), 0); err == nil {
		t.Fatal("a non-PNG was accepted")
	}
	if _, err := reencode(raw[:40], 0); err == nil {
		t.Fatal("a truncated PNG was accepted")
	}
}

// A capture becomes the RFC-081 evidence shape; text is one clean line; a
// page that never answered yields nothing.
func TestEvidence(t *testing.T) {
	now := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	ev := evidence("https://app.example.com/", shot{
		FinalURL: "https://app.example.com/login", StatusCode: 200, Title: "Sign\u202ein\n<b>x</b>" + strings.Repeat("é", 400),
		Server: "nginx", ContentType: "text/html", PNG: pngOf(t, 32, 20, false),
	}, now, 64<<10)
	if ev == nil {
		t.Fatal("no evidence")
	}
	b, _ := json.Marshal(ev)
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	if back["url"] != "https://app.example.com/" || back["final_url"] != "https://app.example.com/login" ||
		back["status_code"].(float64) != 200 || back["captured_at"] != "2026-11-05T08:00:00Z" {
		t.Fatalf("evidence %s", b)
	}
	title := back["title"].(string)
	if len(title) > maxTitleBytes || strings.ContainsAny(title, "\n\u202e") || !strings.HasPrefix(title, "Sign in <b>x</b>") {
		t.Fatalf("title %q", title)
	}
	shotm := back["screenshot"].(map[string]any)
	data, err := base64.StdEncoding.DecodeString(shotm["data"].(string))
	if err != nil || shotm["media_type"] != "image/png" || !bytes.HasPrefix(data, []byte("\x89PNG")) {
		t.Fatalf("screenshot %v %v", shotm["media_type"], err)
	}
	if evidence("https://app.example.com/", shot{Err: "net::ERR_CONNECTION_REFUSED"}, now, 0) != nil {
		t.Fatal("evidence for a page that never answered")
	}
	if ev := evidence("https://app.example.com/", shot{StatusCode: 503, FinalURL: "javascript:alert(1)"}, now, 0); ev == nil || ev["final_url"] != nil {
		t.Fatalf("status-only evidence: %v", ev)
	}
}

// Only an http(s) origin is a target; the browser opens its root.
func TestOriginURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://app.example.com":       "https://app.example.com/",
		"http://app.example.com:8080/x": "http://app.example.com:8080/",
	} {
		u, err := originURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%s: %v %v", in, u, err)
		}
	}
	for _, bad := range []string{"file:///etc/passwd", "chrome://version", "javascript:alert(1)", "app.example.com", "https://u:p@app.example.com", "data:text/html,x"} {
		if _, err := originURL(bad); err == nil {
			t.Errorf("%s accepted as a target", bad)
		}
	}
}

func TestConfigBounds(t *testing.T) {
	c := Config{PageTimeout: 1000, MaxRequests: 1, MaxImageKB: 99999}.withDefaults()
	if c.PageTimeout != 60 || c.MaxRequests != 10 || c.MaxImageKB != 640 {
		t.Fatalf("bounds %+v", c)
	}
	if d := (Config{}).withDefaults(); d.PageTimeout != 15 || d.MaxRequests != 150 || d.MaxImageKB != 640 || d.FullPage {
		t.Fatalf("defaults %+v", d)
	}
	if err := Manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if Manifest.Permissions.Sandbox != "browser" {
		t.Fatal("webshot must run in the browser sandbox")
	}
}

// The protocol connection frames messages on NUL bytes, matches replies to
// commands, hands events to the handler and fails pending commands when the
// browser goes away.
func TestConn(t *testing.T) {
	toBrowserR, toBrowserW := io.Pipe()
	fromBrowserR, fromBrowserW := io.Pipe()
	events := make(chan event, 4)
	c := newConn(toBrowserW, fromBrowserR, func(e event) { events <- e })
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 4096)
		for {
			n, err := toBrowserR.Read(tmp)
			if err != nil {
				return
			}
			buf = append(buf, tmp[:n]...)
			for {
				i := bytes.IndexByte(buf, 0)
				if i < 0 {
					break
				}
				var m message
				_ = json.Unmarshal(buf[:i], &m)
				buf = buf[i+1:]
				_, _ = fromBrowserW.Write([]byte(`{"method":"Page.loadEventFired","sessionId":"s1","params":{}}` + "\x00"))
				reply, _ := json.Marshal(message{ID: m.ID, Result: json.RawMessage(`{"product":"Fake/1"}`)})
				_, _ = fromBrowserW.Write(append(reply, 0))
			}
		}
	}()
	var ver struct {
		Product string `json:"product"`
	}
	if err := c.send(context.Background(), "", "Browser.getVersion", nil, &ver); err != nil || ver.Product != "Fake/1" {
		t.Fatalf("%v %+v", err, ver)
	}
	select {
	case e := <-events:
		if e.Method != "Page.loadEventFired" || e.SessionID != "s1" {
			t.Fatalf("event %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	_ = fromBrowserW.Close()
	<-c.done
	if err := c.send(context.Background(), "", "Browser.getVersion", nil, nil); err == nil {
		t.Fatal("a command on a closed connection succeeded")
	}
}

// SECURITY: Chromium's own sandbox is never turned off, and nothing reaches
// the network but through the task's relay.
func TestLaunchFlagsKeepTheSandbox(t *testing.T) {
	flags := launchFlags("http://127.0.0.1:1080", "/task/profile")
	joined := strings.Join(flags, " ")
	for _, bad := range []string{"--no-sandbox", "--disable-setuid-sandbox", "--single-process", "--no-zygote",
		"--disable-web-security", "--remote-debugging-port", "--allow-file-access", "--disable-seccomp-filter-sandbox",
		"--remote-allow-origins", "--load-extension", "--ignore-certificate-errors"} {
		if strings.Contains(joined, bad) {
			t.Errorf("launch flags carry %s", bad)
		}
	}
	for _, want := range []string{"--remote-debugging-pipe", "--proxy-server=http://127.0.0.1:1080", "--proxy-bypass-list=<-loopback>",
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--user-data-dir=/task/profile", "--disable-extensions", "--block-new-web-contents"} {
		if !strings.Contains(joined, want) {
			t.Errorf("launch flags lack %s", want)
		}
	}
}

// fakeCDP answers every command of a browser connection with success,
// except the methods in fail, and records the commands in order (and the
// expression of each Runtime.evaluate, as "eval:<expression>").
func fakeCDP(t *testing.T, fail map[string]bool) (*conn, func() []string) {
	t.Helper()
	toBrowserR, toBrowserW := io.Pipe()
	fromBrowserR, fromBrowserW := io.Pipe()
	c := newConn(toBrowserW, fromBrowserR, nil)
	var mu sync.Mutex
	var methods []string
	go func() {
		sc := bufio.NewScanner(toBrowserR)
		sc.Split(splitNUL)
		for sc.Scan() {
			var m message
			_ = json.Unmarshal(sc.Bytes(), &m)
			mu.Lock()
			methods = append(methods, m.Method)
			if m.Method == "Runtime.evaluate" {
				var p struct {
					Expression string `json:"expression"`
				}
				_ = json.Unmarshal(m.Params, &p)
				methods = append(methods, "eval:"+p.Expression)
			}
			mu.Unlock()
			reply := message{ID: m.ID, Result: json.RawMessage(`{}`)}
			if fail[m.Method] {
				reply = message{ID: m.ID, Error: &protoError{Code: -32000, Message: "refused"}}
			}
			b, _ := json.Marshal(reply)
			_, _ = fromBrowserW.Write(append(b, 0))
		}
	}()
	t.Cleanup(func() { _ = fromBrowserW.Close(); _ = toBrowserW.Close() })
	return c, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), methods...) }
}

// SECURITY: a target whose interception or auto-attach cannot be set up is
// closed and never resumed (resuming it would run its scripts with no policy
// on its requests or its children's); the refusal is counted.
func TestOnAttachedSetupFailureClosesTarget(t *testing.T) {
	for _, failing := range []string{"Fetch.enable", "Target.setAutoAttach"} {
		t.Run(failing, func(t *testing.T) {
			c, methods := fakeCDP(t, map[string]bool{failing: true})
			b := &browser{c: c, policy: &requestPolicy{}, pages: map[string]*page{}, owners: map[string]*page{},
				attached: map[string]chan string{}, synthetic: map[string]bool{}, refused: map[string]int{}}
			b.onAttached("", "s1", "t1", "page")
			got := methods()
			if !slices.Contains(got, "Target.closeTarget") {
				t.Errorf("the target was not closed: %v", got)
			}
			if slices.Contains(got, "Runtime.runIfWaitingForDebugger") {
				t.Errorf("the target was resumed: %v", got)
			}
			if n := b.refusals(); len(n) == 0 {
				t.Errorf("no refusal counted: %v", n)
			}
		})
	}
	// With everything set up the target is resumed.
	c, methods := fakeCDP(t, nil)
	b := &browser{c: c, policy: &requestPolicy{}, pages: map[string]*page{}, owners: map[string]*page{},
		attached: map[string]chan string{}, synthetic: map[string]bool{}, refused: map[string]int{}}
	b.onAttached("", "s1", "t1", "page")
	if got := methods(); !slices.Contains(got, "Runtime.runIfWaitingForDebugger") || slices.Contains(got, "Target.closeTarget") {
		t.Errorf("a set-up target: %v", got)
	}
}

// SECURITY: a worker is never resumed when its interception cannot be set
// up (Chromium has no Fetch domain on a dedicated worker), and shared and
// service workers are refused by policy. None of them is closed with
// Target.closeTarget either: that only detaches its debugger, which resumes
// it, and it then runs its script with no check on its requests. A worker
// closes itself while it waits; a target that cannot is held on its thread.
func TestOnAttachedWorkersNeverRun(t *testing.T) {
	cases := []struct {
		kind, failing, reason, ends string
	}{
		{"worker", "Fetch.enable", "setup_fetch", workerCloseScript},
		{"worker", "Target.setAutoAttach", "setup_auto_attach", workerCloseScript},
		{"iframe", "Fetch.enable", "setup_fetch", holdScript},
		{"shared_worker", "", "target_kind", workerCloseScript},
		{"service_worker", "", "target_kind", holdScript},
		{"worklet", "", "target_kind", holdScript},
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.failing, func(t *testing.T) {
			c, methods := fakeCDP(t, map[string]bool{tc.failing: true})
			b := &browser{c: c, policy: &requestPolicy{}, pages: map[string]*page{}, owners: map[string]*page{},
				attached: map[string]chan string{}, synthetic: map[string]bool{}, refused: map[string]int{}}
			b.onAttached("p1", "s1", "t1", tc.kind)
			got := waitFor(t, methods, "eval:"+tc.ends)
			for _, m := range []string{"Runtime.runIfWaitingForDebugger", "Target.closeTarget", "Target.detachFromTarget"} {
				if slices.Contains(got, m) {
					t.Errorf("%s: %v", m, got)
				}
			}
			if n := b.refusals(); n[tc.reason] != 1 {
				t.Errorf("refusals %v, want %s", n, tc.reason)
			}
		})
	}
	// A worker whose close fails is held instead.
	c, methods := fakeCDP(t, map[string]bool{"Fetch.enable": true, "Runtime.evaluate": true})
	b := &browser{c: c, policy: &requestPolicy{}, pages: map[string]*page{}, owners: map[string]*page{},
		attached: map[string]chan string{}, synthetic: map[string]bool{}, refused: map[string]int{}}
	b.onAttached("p1", "s1", "t1", "worker")
	if got := waitFor(t, methods, "eval:"+holdScript); slices.Contains(got, "Runtime.runIfWaitingForDebugger") {
		t.Errorf("a worker that did not close: %v", got)
	}
	// Over the target budget a worker is ended as well.
	c, methods = fakeCDP(t, nil)
	b = &browser{c: c, policy: &requestPolicy{}, pages: map[string]*page{}, owners: map[string]*page{},
		attached: map[string]chan string{}, synthetic: map[string]bool{}, refused: map[string]int{}}
	b.nTargets.Store(maxTargets)
	b.onAttached("p1", "s1", "t1", "worker")
	if got := methods(); !slices.Equal(got, []string{"Runtime.evaluate", "eval:" + workerCloseScript}) {
		t.Errorf("a worker over the budget: %v", got)
	}
	if n := b.refusals(); n["targets"] != 1 {
		t.Errorf("refusals %v", n)
	}
}

// waitFor waits until the recorded commands hold want (a command sent
// without waiting for its reply is recorded a moment later).
func waitFor(t *testing.T, methods func() []string, want string) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := methods()
		if slices.Contains(got, want) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s in %v", want, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A capture whose download policy cannot be set fails: a page must not be
// able to save a file on the sensor.
func TestCaptureFailsWhenDownloadsCannotBeDenied(t *testing.T) {
	c, methods := fakeCDP(t, map[string]bool{"Browser.setDownloadBehavior": true})
	b := &browser{c: c, policy: &requestPolicy{}, pages: map[string]*page{}, owners: map[string]*page{},
		attached: map[string]chan string{}, synthetic: map[string]bool{}, refused: map[string]int{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := b.capture(ctx, "http://app.test/", captureOptions{})
	if !strings.HasPrefix(res.Err, "downloads:") {
		t.Fatalf("capture error %q", res.Err)
	}
	if slices.Contains(methods(), "Target.createTarget") {
		t.Fatal("a page was opened without the download policy")
	}
}
