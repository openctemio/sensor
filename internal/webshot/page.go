package webshot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// page is one capture's top-level page and what its events said.
type page struct {
	session   string
	dialogs   atomic.Int64
	requests  atomic.Int64
	stopped   atomic.Bool
	loaded    chan struct{}
	loadOnce  sync.Once
	mu        sync.Mutex
	mainFrame string
	finalURL  string
	status    int
	server    string
	mimeType  string
	crashed   bool
}

func newPage(session string) *page {
	return &page{session: session, loaded: make(chan struct{})}
}

// stopScripts ends the page's running script and turns scripts off: a page
// that loops, or opens dialogs without end, still gets its picture taken.
func (pg *page) stopScripts(c *conn) {
	if !pg.stopped.CompareAndSwap(false, true) {
		return
	}
	c.sendNoWait(pg.session, "Runtime.terminateExecution", nil)
	c.sendNoWait(pg.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": true})
}

func (pg *page) onEvent(e event) {
	switch e.Method {
	case "Page.loadEventFired":
		if e.SessionID == pg.session {
			pg.loadOnce.Do(func() { close(pg.loaded) })
		}
	case "Page.lifecycleEvent", "Page.frameStoppedLoading":
		// The main frame is done: loaded, or the network went quiet, or it
		// stopped loading (a navigation the policy refused stops it too).
		var p struct {
			FrameID string `json:"frameId"`
			Name    string `json:"name"`
		}
		if e.SessionID != pg.session || json.Unmarshal(e.Params, &p) != nil {
			return
		}
		pg.mu.Lock()
		main := p.FrameID != "" && p.FrameID == pg.mainFrame
		pg.mu.Unlock()
		if main && (e.Method == "Page.frameStoppedLoading" || p.Name == "load" || p.Name == "networkIdle") {
			pg.loadOnce.Do(func() { close(pg.loaded) })
		}
	case "Page.frameNavigated":
		var p struct {
			Frame struct {
				ID       string `json:"id"`
				ParentID string `json:"parentId"`
				URL      string `json:"url"`
			} `json:"frame"`
		}
		if e.SessionID != pg.session || json.Unmarshal(e.Params, &p) != nil || p.Frame.ParentID != "" {
			return
		}
		pg.mu.Lock()
		pg.mainFrame, pg.finalURL = p.Frame.ID, p.Frame.URL
		pg.mu.Unlock()
	case "Network.responseReceived":
		var p struct {
			Type     string `json:"type"`
			FrameID  string `json:"frameId"`
			Response struct {
				URL      string         `json:"url"`
				Status   int            `json:"status"`
				MimeType string         `json:"mimeType"`
				Headers  map[string]any `json:"headers"`
			} `json:"response"`
		}
		if e.SessionID != pg.session || json.Unmarshal(e.Params, &p) != nil || p.Type != "Document" {
			return
		}
		pg.mu.Lock()
		if pg.mainFrame == "" || p.FrameID == pg.mainFrame {
			pg.status, pg.mimeType = p.Response.Status, p.Response.MimeType
			pg.server = headerValue(p.Response.Headers, "server")
		}
		pg.mu.Unlock()
	case "Inspector.targetCrashed":
		pg.mu.Lock()
		pg.crashed = true
		pg.mu.Unlock()
		pg.loadOnce.Do(func() { close(pg.loaded) })
	}
}

func headerValue(h map[string]any, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			s, _ := v.(string)
			return s
		}
	}
	return ""
}

// shot is what one capture produced: the page's metadata and the raw image
// the browser returned (re-encoded by the caller before it leaves the
// task).
type shot struct {
	FinalURL    string
	StatusCode  int
	Title       string
	Server      string
	ContentType string
	PNG         []byte
	// Err says why there is no image (the navigation failed, the page
	// crashed or did not paint in time).
	Err string
}

// captureOptions bound one capture.
type captureOptions struct {
	// PageTimeout bounds the navigation and load.
	PageTimeout time.Duration
	FullPage    bool
}

// capture loads url in a fresh browser context (no cookies, storage or
// cache shared with another capture) and takes its picture.
func (b *browser) capture(ctx context.Context, url string, o captureOptions) shot {
	var res shot
	c := b.c
	var bctx struct {
		ID string `json:"browserContextId"`
	}
	if err := c.send(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &bctx); err != nil {
		res.Err = "browser context: " + err.Error()
		return res
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
		_ = c.send(dctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bctx.ID}, nil)
		cancel()
	}()
	// Nothing is ever saved to disk.
	if err := c.send(ctx, "", "Browser.setDownloadBehavior", map[string]any{"behavior": "deny", "browserContextId": bctx.ID}, nil); err != nil {
		res.Err = "downloads: " + err.Error()
		return res
	}
	b.nTargets.Store(0)
	b.unowned.Store(0)

	var tgt struct {
		ID string `json:"targetId"`
	}
	if err := c.send(ctx, "", "Target.createTarget", map[string]any{
		"url": "about:blank", "browserContextId": bctx.ID, "width": viewportWidth, "height": viewportHeight,
	}, &tgt); err != nil {
		res.Err = "page: " + err.Error()
		return res
	}
	var session string
	select {
	case session = <-b.attachedCh(tgt.ID):
	case <-time.After(stepTimeout):
		res.Err = "page: not attached"
		return res
	case <-ctx.Done():
		res.Err = ctx.Err().Error()
		return res
	}
	pg := newPage(session)
	b.mu.Lock()
	b.pages[session] = pg
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pages, session)
		for s, owner := range b.owners {
			if owner == pg {
				delete(b.owners, s)
			}
		}
		delete(b.attached, tgt.ID)
		b.mu.Unlock()
	}()

	nctx, cancel := context.WithTimeout(ctx, o.PageTimeout)
	defer cancel()
	var nav struct {
		ErrorText string `json:"errorText"`
	}
	if err := c.send(nctx, session, "Page.navigate", map[string]any{"url": url}, &nav); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		res.Err = "navigate: " + err.Error()
		return res
	}
	if nav.ErrorText != "" {
		res.Err = "navigate: " + nav.ErrorText
		pg.fill(&res)
		return res
	}
	select {
	case <-pg.loaded:
		// Late paints (web fonts, images) get a short moment.
		select {
		case <-time.After(settleDelay):
		case <-nctx.Done():
		}
	case <-nctx.Done():
	}
	if ctx.Err() != nil {
		res.Err = ctx.Err().Error()
		return res
	}
	// Whatever the page still runs stops now: the title and the picture
	// must not wait on a script.
	pg.stopScripts(c)
	pg.fill(&res)
	if pg.isCrashed() {
		res.Err = "the page crashed"
		return res
	}

	// The title as the browser holds it: no script runs to read it.
	tctx, tcancel := context.WithTimeout(ctx, stepTimeout)
	var info struct {
		TargetInfo struct {
			Title string `json:"title"`
			URL   string `json:"url"`
		} `json:"targetInfo"`
	}
	if c.send(tctx, "", "Target.getTargetInfo", map[string]any{"targetId": tgt.ID}, &info) == nil {
		if t := info.TargetInfo.Title; t != "" && !isURLTitle(t, info.TargetInfo.URL) {
			res.Title = t
		}
	}
	tcancel()

	png, err := b.screenshot(ctx, session, o.FullPage)
	if err != nil {
		res.Err = "screenshot: " + err.Error()
		return res
	}
	res.PNG = png
	return res
}

func (pg *page) fill(res *shot) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	res.FinalURL, res.StatusCode, res.Server, res.ContentType = pg.finalURL, pg.status, pg.server, pg.mimeType
}

func (pg *page) isCrashed() bool {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.crashed
}

// screenshot is the page's picture: the viewport, or the page from its top
// down to fullPageMaxHeight, at most viewportWidth wide whatever the page
// claims its size is (a hostile page may claim any size).
func (b *browser) screenshot(ctx context.Context, session string, fullPage bool) ([]byte, error) {
	sctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	w, h := float64(viewportWidth), float64(viewportHeight)
	if fullPage {
		var m struct {
			Content struct {
				Height float64 `json:"height"`
			} `json:"cssContentSize"`
		}
		if err := b.c.send(sctx, session, "Page.getLayoutMetrics", nil, &m); err == nil &&
			!math.IsNaN(m.Content.Height) && m.Content.Height > h {
			h = math.Min(m.Content.Height, fullPageMaxHeight)
		}
	}
	var out struct {
		Data string `json:"data"`
	}
	if err := b.c.send(sctx, session, "Page.captureScreenshot", map[string]any{
		"format": "png", "fromSurface": true, "captureBeyondViewport": fullPage,
		"clip": map[string]any{"x": 0, "y": 0, "width": w, "height": h, "scale": 1},
	}, &out); err != nil {
		return nil, err
	}
	if base64.StdEncoding.DecodedLen(len(out.Data)) > maxRawImage {
		return nil, fmt.Errorf("the image is over %d bytes", maxRawImage)
	}
	return base64.StdEncoding.DecodeString(out.Data)
}

// maxRawImage bounds the image the browser hands back, before re-encoding.
const maxRawImage = 24 << 20

// isURLTitle reports a title the browser made from the URL (a page without
// a <title>).
func isURLTitle(title, u string) bool {
	if title == u {
		return true
	}
	_, rest, ok := strings.Cut(u, "://")
	return ok && (title == rest || title == strings.TrimSuffix(rest, "/"))
}
