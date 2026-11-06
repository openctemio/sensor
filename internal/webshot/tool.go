// Package webshot is the sensor's screenshot tool (capability
// capture.screenshot@1; api RFC-081): headless Chromium loads each web
// origin of the task and the tool reports the picture, with the page's
// status, title and server, as the origin's web evidence.
//
// The browser runs a target's scripts, so the tool is built to contain it:
//
//   - the task runs only confined (sdk-go permissions.sandbox browser): its
//     network namespace has loopback and the relay to its forwarder only,
//     and the forwarder admits the job's targets alone;
//   - Chromium's own sandbox stays on: its renderers run in Chromium's user,
//     PID and network namespaces and its seccomp policy, inside ours;
//   - every request is paused and checked before it leaves the browser:
//     http and https only, GET and HEAD only, the job's targets and web
//     scope only, a request budget per page; downloads, the file chooser,
//     permission prompts, new windows and WebRTC's UDP are off;
//   - one browser per task with its profile in the task directory (removed
//     with the task), one fresh browser context per target;
//   - a page has a time budget; past it its scripts are stopped, dialogs are
//     dismissed, and the picture is capped in size and pixels and re-encoded
//     (no metadata survives).
package webshot

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/egressenv"
	"github.com/openctemio/sensor/internal/toolrun"
)

// ToolYAML is the tool's descriptor (OpenCTEM Tool Contract v1).
//
//go:embed tool.yaml
var ToolYAML []byte

// Manifest describes the webshot tool.
var Manifest = toolrun.MustManifest(ToolYAML)

// Tool runs webshot in the tool child.
var Tool = toolrun.Register(tool.New(Manifest, run))

var settingsSchema = core.MustParseSettingsSchema(string(Manifest.Config))

// PropertyKey is the asset property the platform reads captures from
// (RFC-081 §3).
const PropertyKey = "web_evidence"

// EnvBrowser names the browser binary (default DefaultBrowser).
const EnvBrowser = "OPENCTEM_WEBSHOT_BROWSER"

// DefaultBrowser is where the sensor's browser image installs Chromium's
// headless shell.
const DefaultBrowser = "/usr/lib/chromium/chromium-headless-shell"

// Config is the tool's configuration (tool.yaml config).
type Config struct {
	PageTimeout int  `json:"page_timeout,omitempty"`
	FullPage    bool `json:"full_page,omitempty"`
	MaxRequests int  `json:"max_requests,omitempty"`
	MaxImageKB  int  `json:"max_image_kb,omitempty"`
}

// withDefaults bounds every value (the schema does too; the child does not
// trust that it ran).
func (c Config) withDefaults() Config {
	c.PageTimeout = clampInt(c.PageTimeout, 5, 60, 15)
	c.MaxRequests = clampInt(c.MaxRequests, 10, 500, 150)
	c.MaxImageKB = clampInt(c.MaxImageKB, 64, 640, 640)
	return c
}

func clampInt(v, lo, hi, def int) int {
	switch {
	case v == 0:
		return def
	case v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

// Local is what the sensor hands its child: the resolved settings and the
// browser binary it found. Never platform input.
type Local struct {
	Config  json.RawMessage `json:"config,omitempty"`
	Browser string          `json:"browser,omitempty"`
}

// maxTitleBytes bounds the reported title (the platform keeps 300 bytes).
const maxTitleBytes = 300

// errUnconfined: the tool never runs a browser outside a confined task.
var errUnconfined = errors.New("webshot runs a web browser only in a task sandbox that confines its network")

func run(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
	var local Local
	if len(task.Local) > 0 {
		if err := json.Unmarshal(task.Local, &local); err != nil {
			return tool.Invalid("webshot: the sensor's configuration is unreadable")
		}
	}
	var cfg Config
	for _, raw := range []json.RawMessage{task.Config, local.Config} {
		if len(raw) > 0 && json.Unmarshal(raw, &cfg) != nil {
			return tool.Invalid("webshot: the configuration is unreadable")
		}
	}
	cfg = cfg.withDefaults()
	// The sandbox refuses an unconfined browser task already; the tool
	// checks again on its side.
	proxy := egressenv.Proxy()
	if proxy == "" {
		return tool.Refused(errUnconfined.Error())
	}
	bin := local.Browser
	if bin == "" {
		bin = DefaultBrowser
	}

	var targets []tool.Target
	var urls []*url.URL
	for _, t := range task.Targets {
		u, err := originURL(t.Value)
		if err != nil {
			ctx.TargetSkipped(t, err.Error())
			continue
		}
		targets = append(targets, t)
		urls = append(urls, u)
	}
	if len(targets) == 0 {
		return nil
	}
	policy := newRequestPolicy(urls, task.WebScope)
	policy.maxRequests = cfg.MaxRequests
	ua, headers := identity(task)

	work := ctx.Workdir()
	env := browserEnv(work)
	var b *browser
	start := func() error {
		var err error
		b, err = startBrowser(ctx, bin, proxy, filepath.Join(work, "profile"), env, policy, ua, headers, insecureTLS(task))
		return err
	}
	if err := start(); err != nil {
		return tool.Failed(err)
	}
	defer func() { b.close() }()
	if ua == "" {
		// The browser's own User-Agent with the tool's name after it, so a
		// target can tell who looked.
		b.ua = b.userAgent + " openctem-" + Manifest.Name + "/" + Manifest.Version
	}

	opts := captureOptions{PageTimeout: time.Duration(cfg.PageTimeout) * time.Second, FullPage: cfg.FullPage}
	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		ctx.Progress(i, len(targets), t.Value)
		if b.dead() {
			// A crash of the browser (a hostile page) ends only its page.
			if err := start(); err != nil {
				ctx.TargetError(t, tool.Failed(err))
				continue
			}
		}
		tctx, cancel := context.WithTimeout(ctx, opts.PageTimeout+2*stepTimeout+5*time.Second)
		s := b.capture(tctx, urls[i].String(), opts)
		cancel()
		ev := evidence(urls[i].String(), s, time.Now(), cfg.MaxImageKB<<10)
		if ev == nil {
			ctx.TargetError(t, tool.Unreachable(errors.New(capDetail(s.Err))))
			continue
		}
		if s.Err != "" {
			ctx.Log().Info("webshot: capture without a picture", "reason", capDetail(s.Err))
		}
		a := ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: t.Value,
			Properties: ctis.Properties{PropertyKey: []any{ev}}}
		if err := ctx.Emit().Asset(a); err != nil {
			return err
		}
		ctx.TargetDone(t)
	}
	if r := b.refusals(); len(r) > 0 {
		args := make([]any, 0, 2*len(r))
		for k, v := range r {
			args = append(args, k, v)
		}
		ctx.Log().Info("webshot: requests and targets refused by the page policy", args...)
	}
	return nil
}

// originURL is a target as the URL the browser opens: an http or https
// origin (its root path).
func originURL(v string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("not an http or https web origin")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}, nil
}

// identity is the job's User-Agent and headers every request carries.
func identity(task tool.Task) (string, map[string]string) {
	var ua string
	headers := map[string]string{}
	if task.HTTP != nil {
		ua = task.HTTP.UserAgent
		for k, v := range task.HTTP.Headers {
			headers[k] = v
		}
	}
	if task.Identity != nil {
		if task.Identity.UserAgent != "" {
			ua = task.Identity.UserAgent
		}
		for k, v := range task.Identity.Headers {
			headers[k] = v
		}
	}
	return ua, headers
}

// insecureTLS reports whether the task's HTTP settings accept any
// certificate from its targets.
func insecureTLS(task tool.Task) bool {
	return task.HTTP != nil && task.HTTP.TLS != nil && task.HTTP.TLS.InsecureSkipVerify
}

// browserEnv is the browser's whole environment: its home, temporary and
// cache directories in the task directory, nothing of the sensor's.
func browserEnv(work string) []string {
	home := filepath.Join(work, "home")
	tmp := filepath.Join(work, "tmp")
	for _, d := range []string{home, tmp} {
		_ = os.MkdirAll(d, 0o700)
	}
	return []string{
		"HOME=" + home, "TMPDIR=" + tmp, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "LANG=C.UTF-8", "PATH=/usr/bin:/bin",
	}
}

// evidence is one RFC-081 capture of a shot, or nil when the page never
// answered (no status and no picture).
func evidence(target string, s shot, now time.Time, imageLimit int) map[string]any {
	ev := map[string]any{"url": target, "captured_at": now.UTC().Format(time.RFC3339)}
	if s.FinalURL != "" && s.FinalURL != target && (strings.HasPrefix(s.FinalURL, "http://") || strings.HasPrefix(s.FinalURL, "https://")) {
		ev["final_url"] = s.FinalURL
	}
	if s.StatusCode >= 100 && s.StatusCode <= 599 {
		ev["status_code"] = s.StatusCode
	}
	if t := clipText(s.Title, maxTitleBytes); t != "" {
		ev["title"] = t
	}
	if v := clipText(s.Server, 200); v != "" {
		ev["server"] = v
	}
	if v := clipText(s.ContentType, 100); v != "" {
		ev["content_type"] = v
	}
	hasShot := false
	if len(s.PNG) > 0 {
		if img, err := reencode(s.PNG, imageLimit); err == nil {
			ev["screenshot"] = map[string]any{"media_type": img.MediaType, "data": base64.StdEncoding.EncodeToString(img.Data)}
			hasShot = true
		}
	}
	if !hasShot && ev["status_code"] == nil {
		return nil
	}
	return ev
}

// clipText is s on one line, without control characters, cut to n bytes on
// a character boundary.
func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// capDetail bounds an error detail; it never carries page content.
func capDetail(s string) string {
	if s == "" {
		return "the page did not answer"
	}
	return tool.CapDetail(fmt.Sprintf("webshot: %s", s))
}
