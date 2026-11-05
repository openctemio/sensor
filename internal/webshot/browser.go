package webshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The browser: one headless Chromium per task, started by the tool child
// inside the task sandbox, so it inherits the task's network namespace
// (loopback and the relay to the forwarder only), its Landlock rules,
// seccomp filter, resource limits and no_new_privs. Chromium's own sandbox
// stays on (no --no-sandbox): its renderers run in Chromium's namespaces
// and its much tighter seccomp policy, inside ours.

// viewport is the page size every capture renders at.
const (
	viewportWidth  = 1280
	viewportHeight = 800
	// fullPageMaxHeight bounds a full-page capture (the platform keeps at
	// most 1920x2400 pixels).
	fullPageMaxHeight = 2400
)

// Bounds that stop a hostile page from keeping the browser busy.
const (
	// maxDialogs: after this many alert/confirm/prompt dialogs on one page
	// its scripts are stopped.
	maxDialogs = 20
	// maxTargets bounds the pages, frames and workers one capture may open;
	// beyond it new ones are closed before they run.
	maxTargets = 32
	// settleDelay is how long a loaded page may still paint.
	settleDelay = 750 * time.Millisecond
	// stepTimeout bounds one protocol step (title, metrics, screenshot).
	stepTimeout = 10 * time.Second
	// startTimeout bounds the browser's start.
	startTimeout = 30 * time.Second
)

// launchFlags are the browser's command-line flags. proxy is the task's
// relay ("http://127.0.0.1:1080"); profile the per-task profile directory.
func launchFlags(proxy, profile string) []string {
	return []string{
		"--headless",
		"--remote-debugging-pipe",
		"--user-data-dir=" + profile,
		"--disk-cache-dir=" + filepath.Join(profile, "cache"),
		"--disk-cache-size=33554432",
		"--no-first-run",
		"--no-default-browser-check",
		"--no-service-autorun",
		"--no-pings",
		"--noerrdialogs",
		"--password-store=basic",
		"--use-mock-keychain",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-extensions",
		"--disable-component-extensions-with-background-pages",
		"--disable-component-update",
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-sync",
		"--disable-domain-reliability",
		"--disable-client-side-phishing-detection",
		"--disable-breakpad",
		"--disable-crash-reporter",
		"--disable-notifications",
		"--disable-file-system",
		"--disable-remote-fonts",
		"--deny-permission-prompts",
		"--block-new-web-contents",
		"--mute-audio",
		"--hide-scrollbars",
		"--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,AutofillServerCommunication," +
			"CertificateTransparencyComponentUpdater,InterestFeedContentSuggestions,PrivacySandboxSettings4,AcceptCHFrame," +
			"BackForwardCache,Prerender2,DnsHttpssvc,AsyncDns",
		// Every request goes to the task's relay; nothing is resolved
		// locally (the forwarder resolves, checks the address against the
		// job and pins it); loopback is not exempt from the proxy, so a page
		// cannot reach the relay or anything else on the task's loopback.
		"--proxy-server=" + proxy,
		"--proxy-bypass-list=<-loopback>",
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE " + proxyHost(proxy),
		// WebRTC would send UDP around the proxy.
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		fmt.Sprintf("--window-size=%d,%d", viewportWidth, viewportHeight),
		"about:blank",
	}
}

// proxyHost is the host of the proxy URL (the relay's loopback address): the
// one name the browser may resolve, so it can reach its proxy.
func proxyHost(proxy string) string {
	u, err := url.Parse(proxy)
	if err != nil || u.Hostname() == "" {
		return "127.0.0.1"
	}
	return u.Hostname()
}

// browser is a running Chromium and its protocol connection.
type browser struct {
	cmd     *exec.Cmd
	c       *conn
	stderr  *capped
	exited  chan struct{}
	policy  *requestPolicy
	headers map[string]string
	ua      string
	// userAgent is the browser's own User-Agent.
	userAgent string

	mu       sync.Mutex
	pages    map[string]*page // by session id: the page of a top-level target
	owners   map[string]*page // by session id: the page a child session belongs to
	attached map[string]chan string
	// synthetic are the network ids of refused navigations answered 204:
	// their response is not the page's.
	synthetic map[string]bool
	refused   map[string]int
	nTargets  atomic.Int64
	// unowned counts the requests of targets that belong to no page.
	unowned atomic.Int64
}

// errNoBrowser: the browser binary is missing or does not start.
var errNoBrowser = errors.New("webshot: the browser does not start")

// startBrowser starts Chromium with its protocol on a pipe.
func startBrowser(ctx context.Context, bin, proxy, profile string, env []string, policy *requestPolicy, ua string, headers map[string]string, insecureTLS bool) (*browser, error) {
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return nil, fmt.Errorf("webshot: profile: %w", err)
	}
	// fd 3: the browser reads commands; fd 4: the browser writes.
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = cmdR.Close()
		_ = cmdW.Close()
		return nil, err
	}
	b := &browser{
		stderr: &capped{max: 8 << 10}, exited: make(chan struct{}), policy: policy, headers: headers, ua: ua,
		pages: map[string]*page{}, owners: map[string]*page{}, attached: map[string]chan string{}, refused: map[string]int{}, synthetic: map[string]bool{},
	}
	cmd := exec.Command(bin, launchFlags(proxy, profile)...) //nolint:gosec // the configured browser binary
	cmd.Env = env
	cmd.Dir = profile
	cmd.Stdout = b.stderr
	cmd.Stderr = b.stderr
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	// Its own process group, so the whole tree (zygote, renderers, utility
	// processes) is killed with it.
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		_ = cmdR.Close()
		_ = cmdW.Close()
		_ = outR.Close()
		_ = outW.Close()
		return nil, fmt.Errorf("%w: %v", errNoBrowser, err)
	}
	_ = cmdR.Close()
	_ = outW.Close()
	b.cmd = cmd
	go func() {
		_ = cmd.Wait()
		_ = outR.Close()
		close(b.exited)
	}()
	b.c = newConn(cmdW, outR, b.onEvent)

	sctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	var ver struct {
		Product   string `json:"product"`
		UserAgent string `json:"userAgent"`
	}
	if err := b.c.send(sctx, "", "Browser.getVersion", nil, &ver); err != nil {
		b.close()
		return nil, fmt.Errorf("%w: %v (%s); Chromium's sandbox needs the sensor's seccomp profile written from this image (it allows chroot)",
			errNoBrowser, err, b.stderr.firstLine())
	}
	b.userAgent = ver.UserAgent
	if insecureTLS {
		// Only when the job's HTTP settings accept any certificate (the
		// organization's TLS rule): a target with a self-signed or expired
		// certificate is still pictured.
		if err := b.c.send(sctx, "", "Security.setIgnoreCertificateErrors", map[string]any{"ignore": true}, nil); err != nil {
			b.close()
			return nil, fmt.Errorf("%w: TLS settings: %v", errNoBrowser, err)
		}
	}
	// Every new target (page, frame, worker) waits for us before it runs a
	// line of script: its requests are paused and checked from the first.
	if err := b.c.send(sctx, "", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}, nil); err != nil {
		b.close()
		return nil, fmt.Errorf("%w: auto-attach: %v", errNoBrowser, err)
	}
	return b, nil
}

// close ends the browser and its whole process group.
func (b *browser) close() {
	if b.cmd == nil || b.cmd.Process == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = b.c.send(ctx, "", "Browser.close", nil, nil)
	cancel()
	select {
	case <-b.exited:
	case <-time.After(3 * time.Second):
	}
	killGroup(b.cmd)
	<-b.exited
}

// noSocketsScript removes the script APIs whose connections bypass request
// interception (WebSocket, WebTransport, WebRTC). The task's forwarder still
// bounds where such a connection could go; this keeps them from opening at
// all (a T1 capture changes nothing on the target).
const noSocketsScript = `(() => { for (const n of ["WebSocket", "WebSocketStream", "WebTransport", "RTCPeerConnection",
  "webkitRTCPeerConnection", "RTCDataChannel", "RTCSessionDescription"]) {
  try { Object.defineProperty(globalThis, n, { value: undefined, writable: false, configurable: false }); } catch (e) {} } })();`

// dead reports whether the browser exited.
func (b *browser) dead() bool {
	select {
	case <-b.exited:
		return true
	default:
		return false
	}
}

// onEvent handles protocol events on the reader goroutine.
func (b *browser) onEvent(e event) {
	switch e.Method {
	case "Target.attachedToTarget":
		var p struct {
			SessionID  string `json:"sessionId"`
			TargetInfo struct {
				TargetID string `json:"targetId"`
				Type     string `json:"type"`
			} `json:"targetInfo"`
			Waiting bool `json:"waitingForDebugger"`
		}
		if json.Unmarshal(e.Params, &p) != nil {
			return
		}
		go b.onAttached(e.SessionID, p.SessionID, p.TargetInfo.TargetID, p.TargetInfo.Type)
	case "Fetch.requestPaused":
		b.onRequestPaused(e.SessionID, e.Params)
	case "Fetch.authRequired":
		// Never answer a credential challenge (proxy or server).
		var p struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(e.Params, &p) == nil {
			b.c.sendNoWait(e.SessionID, "Fetch.continueWithAuth", map[string]any{
				"requestId": p.RequestID, "authChallengeResponse": map[string]any{"response": "CancelAuth"},
			})
		}
	case "Page.javascriptDialogOpening":
		b.c.sendNoWait(e.SessionID, "Page.handleJavaScriptDialog", map[string]any{"accept": false})
		if pg := b.pageOf(e.SessionID); pg != nil && pg.dialogs.Add(1) == maxDialogs {
			pg.stopScripts(b.c)
		}
	default:
		if e.Method == "Network.responseReceived" && b.isSynthetic(e.Params) {
			return
		}
		if pg := b.pageOf(e.SessionID); pg != nil {
			pg.onEvent(e)
		}
	}
}

// isSynthetic reports a response the policy made (a refused navigation).
func (b *browser) isSynthetic(raw json.RawMessage) bool {
	var p struct {
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.synthetic[p.RequestID]
}

// attachedCh is the channel a page target's session is handed over on: made
// by whichever comes first, the attach event or the capture waiting for it.
func (b *browser) attachedCh(targetID string) chan string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := b.attached[targetID]
	if ch == nil {
		ch = make(chan string, 1)
		b.attached[targetID] = ch
	}
	return ch
}

func (b *browser) pageOf(session string) *page {
	b.mu.Lock()
	defer b.mu.Unlock()
	if pg := b.pages[session]; pg != nil {
		return pg
	}
	return b.owners[session]
}

// onAttached configures a new target before it runs: request interception
// with the policy, then auto-attach for its own children, then resume. A
// target over the budget, or of a kind that renders nothing for us, is
// closed instead.
func (b *browser) onAttached(parent, session, targetID, kind string) {
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	c := b.c
	if b.nTargets.Add(1) > maxTargets {
		b.refuse("targets")
		_ = c.send(ctx, "", "Target.closeTarget", map[string]any{"targetId": targetID}, nil)
		return
	}
	switch kind {
	case "page", "iframe", "worker", "service_worker", "shared_worker":
	default:
		b.refuse("target_kind")
		_ = c.send(ctx, "", "Target.closeTarget", map[string]any{"targetId": targetID}, nil)
		return
	}
	b.mu.Lock()
	if parent != "" {
		owner := b.pages[parent]
		if owner == nil {
			owner = b.owners[parent]
		}
		if owner != nil {
			b.owners[session] = owner
		}
	}
	b.mu.Unlock()

	// A target whose interception cannot be set up must never run: without
	// Fetch its requests would not pass the policy. It stays paused and is
	// closed; it is never resumed.
	if err := c.send(ctx, session, "Fetch.enable", map[string]any{
		"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}, "handleAuthRequests": true,
	}, nil); err != nil {
		b.refuse("setup_fetch")
		_ = c.send(ctx, "", "Target.closeTarget", map[string]any{"targetId": targetID}, nil)
		return
	}
	if kind != "service_worker" && kind != "shared_worker" && kind != "worker" {
		_ = c.send(ctx, session, "Network.enable", map[string]any{"maxTotalBufferSize": 1 << 20, "maxResourceBufferSize": 1 << 18}, nil)
		// WebSockets never reach the Fetch domain: block them here (the
		// current form of the command, then the older one).
		if err := c.send(ctx, session, "Network.setBlockedURLs", map[string]any{"urlPatterns": []map[string]any{
			{"urlPattern": "ws://*", "block": true}, {"urlPattern": "wss://*", "block": true},
		}}, nil); err != nil {
			if err := c.send(ctx, session, "Network.setBlockedURLs", map[string]any{"urls": []string{"ws://*", "wss://*"}}, nil); err != nil {
				b.refuse("setup_blocked_urls")
			}
		}
		if b.ua != "" {
			_ = c.send(ctx, session, "Network.setUserAgentOverride", map[string]any{"userAgent": b.ua}, nil)
		}
	}
	switch kind {
	case "page", "iframe":
		// Script APIs that open connections the Fetch domain never sees are
		// removed before the page's first script runs.
		_ = c.send(ctx, session, "Page.enable", nil, nil)
		if err := c.send(ctx, session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": noSocketsScript, "runImmediately": true}, nil); err != nil {
			b.refuse("setup_no_sockets")
		}
	default:
		_ = c.send(ctx, session, "Runtime.evaluate", map[string]any{"expression": noSocketsScript}, nil)
	}
	if kind == "page" {
		_ = c.send(ctx, session, "Page.setLifecycleEventsEnabled", map[string]any{"enabled": true}, nil)
		_ = c.send(ctx, session, "Page.setInterceptFileChooserDialog", map[string]any{"enabled": true}, nil)
		_ = c.send(ctx, session, "Emulation.setDeviceMetricsOverride", map[string]any{
			"width": viewportWidth, "height": viewportHeight, "deviceScaleFactor": 1, "mobile": false,
		}, nil)
	}
	// Children that cannot be intercepted would run free: close this target
	// instead of resuming it.
	if err := c.send(ctx, session, "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}, nil); err != nil {
		b.refuse("setup_auto_attach")
		_ = c.send(ctx, "", "Target.closeTarget", map[string]any{"targetId": targetID}, nil)
		return
	}
	if kind == "page" {
		// The capture waits for its page's session before it navigates.
		select {
		case b.attachedCh(targetID) <- session:
		default:
		}
	}
	_ = c.send(ctx, session, "Runtime.runIfWaitingForDebugger", nil, nil)
}

// onRequestPaused lets a request go on with the job's identification, or
// fails it.
func (b *browser) onRequestPaused(session string, raw json.RawMessage) {
	var p struct {
		RequestID    string `json:"requestId"`
		NetworkID    string `json:"networkId"`
		ResourceType string `json:"resourceType"`
		Request      struct {
			URL     string            `json:"url"`
			Method  string            `json:"method"`
			Headers map[string]string `json:"headers"`
		} `json:"request"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return
	}
	reason := b.policy.decide(p.Request.Method, p.Request.URL)
	if reason == "" && b.policy.maxRequests > 0 {
		// A request of no known page (a service worker attaches to the
		// browser, not to its page) counts against the capture's budget.
		counter := &b.unowned
		if pg := b.pageOf(session); pg != nil {
			counter = &pg.requests
		}
		if counter.Add(1) > int64(b.policy.maxRequests) {
			reason = refuseBudget
		}
	}
	if reason != "" {
		b.refuse(reason)
		if p.ResourceType == "Document" {
			b.mu.Lock()
			if len(b.synthetic) < 1024 {
				b.synthetic[p.NetworkID] = true
			}
			b.mu.Unlock()
			// A refused navigation (a form post, a redirect out of scope)
			// answers 204: the frame stays on the page it showed, which is
			// the page the capture is of.
			b.c.sendNoWait(session, "Fetch.fulfillRequest", map[string]any{"requestId": p.RequestID, "responseCode": 204})
			return
		}
		b.c.sendNoWait(session, "Fetch.failRequest", map[string]any{"requestId": p.RequestID, "errorReason": "BlockedByClient"})
		return
	}
	if len(b.headers) == 0 && b.ua == "" {
		b.c.sendNoWait(session, "Fetch.continueRequest", map[string]any{"requestId": p.RequestID})
		return
	}
	b.c.sendNoWait(session, "Fetch.continueRequest", map[string]any{
		"requestId": p.RequestID, "headers": withIdentity(p.Request.Headers, b.ua, b.headers),
	})
}

// withIdentity is the request's headers with the job's User-Agent and
// headers set over what the page set.
func withIdentity(h map[string]string, ua string, extra map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(h)+len(extra)+1)
	set := map[string]bool{}
	for k := range extra {
		set[strings.ToLower(k)] = true
	}
	if ua != "" {
		set["user-agent"] = true
	}
	for k, v := range h {
		if !set[strings.ToLower(k)] {
			out = append(out, map[string]string{"name": k, "value": v})
		}
	}
	for k, v := range extra {
		out = append(out, map[string]string{"name": k, "value": v})
	}
	if ua != "" {
		out = append(out, map[string]string{"name": "User-Agent", "value": ua})
	}
	return out
}

func (b *browser) refuse(reason string) {
	b.mu.Lock()
	b.refused[reason]++
	b.mu.Unlock()
}

// refusals are the counts of refused requests and targets, by reason.
func (b *browser) refusals() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.refused))
	for k, v := range b.refused {
		out[k] = v
	}
	return out
}

// capped keeps the first max bytes written to it (the browser's output, for
// a start failure only; never logged with page content).
type capped struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *capped) firstLine() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, _, _ := strings.Cut(strings.TrimSpace(c.buf.String()), "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
