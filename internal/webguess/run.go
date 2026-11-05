package webguess

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/openctemio/contract/edgeprotect"
	"github.com/openctemio/contract/webpath"
	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webdiff"
	"github.com/openctemio/sdk-go/pkg/webscope"
	"github.com/openctemio/sensor/internal/toolrun"
)

// maxCandidates bounds the list read (the slot's max_lines).
const maxCandidates = 300000

// gapOrder is the order in which an origin's gap reasons name its main one:
// what stopped the origin first, then what limited it.
var gapOrder = []string{toolrun.GapNoCandidates, webdiff.GapEdgeProtected, webdiff.GapThrottled, webdiff.GapBlocked, webdiff.GapHostileResponse,
	webdiff.GapProtocol, webdiff.GapBudget, webdiff.GapUnstableBaseline, webdiff.GapAuthWall, webdiff.GapCatchAll,
	webdiff.GapScopeFiltered}

// checkScope refuses a task whose web scope does not bound path discovery:
// there must be one, it must allow only GET and HEAD, and it must cap the
// requests per host. The forwarder enforces it; this keeps the tool from
// starting at all without it (fail closed).
func checkScope(ws *webscope.Scope) error {
	if ws == nil {
		return tool.Refused("webguess runs only under the job's web scope; the job has none")
	}
	if len(ws.Methods) == 0 || slices.ContainsFunc(ws.Methods, func(m string) bool { return m != "GET" && m != "HEAD" }) {
		return tool.Refused("webguess runs only under a web scope that allows GET and HEAD alone")
	}
	if ws.MaxRequestsPerHost <= 0 {
		return tool.Refused("webguess runs only under a web scope that caps the requests per host")
	}
	return ws.Validate()
}

// run is the tool's Run in the child.
func run(ctx tool.Context, task tool.Task, _ json.RawMessage) error {
	cfg, err := readConfig(task)
	if err != nil {
		return err
	}
	if err := checkScope(task.WebScope); err != nil {
		return err
	}
	paths := task.ContentPaths(Slot)
	if len(paths) != 1 {
		return tool.Invalid("webguess: the job carries %d candidate lists (content slot %q); it needs exactly one", len(paths), Slot)
	}
	cands, err := readCandidates(paths[0])
	if err != nil {
		return tool.Invalid("webguess: the candidate list: %v", err)
	}
	hosts := make([]string, 0, len(task.Targets))
	for _, t := range task.Targets {
		if h := t.Host(); h != "" {
			hosts = append(hosts, h)
		}
	}
	budget := min(cfg.MaxRequests, task.WebScope.MaxRequestsPerHost)
	var gaps []adapt.Gap
	for i, t := range task.Targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		ctx.Progress(i, len(task.Targets), "")
		origin, err := originOf(t.Value)
		if err != nil {
			ctx.TargetSkipped(t, err.Error())
			continue
		}
		res, err := probeOrigin(ctx, task.WebScope, hosts, cfg, budget, origin, cands)
		if errors.Is(err, tool.ErrOutputLimit) {
			return err
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ctx.TargetError(t, tool.Unreachable(err))
			continue
		}
		if g, ok := res.gap(); ok {
			gaps = append(gaps, g)
		}
		ctx.Log().Info("webguess: origin done", "origin", fmt.Sprintf("%q", clip(origin, 128)), "candidates", res.checked,
			"filtered", res.filtered, "requests", res.requests, "hits", res.hits, "stopped", res.stopped)
		ctx.TargetDone(t)
	}
	if len(gaps) > 0 {
		var rep ctis.Report
		toolrun.SetReportGaps(&rep, gaps, len(gaps))
		if err := ctx.Emit().Report(&rep); err != nil && errors.Is(err, tool.ErrOutputLimit) {
			return err
		}
	}
	return nil
}

// originResult is what one origin's probe found.
type originResult struct {
	origin            string
	checked, filtered int
	requests, hits    int
	stopped           string
	gaps              map[string]int
	edge              edgeprotect.Verdict
}

// probeOrigin probes the candidates of one origin and emits its hits.
func probeOrigin(ctx tool.Context, ws *webscope.Scope, hosts []string, cfg Config, budget int, origin string, cands []string) (*originResult, error) {
	res := &originResult{origin: origin}
	base, _ := url.Parse(origin)
	allowed := make([]string, 0, len(cands))
	for _, c := range cands {
		if !allowedCandidate(ws, hosts, cfg.ExcludePaths, base, c) {
			res.filtered++
			continue
		}
		allowed = append(allowed, c)
	}
	p, err := webdiff.New(ctx.HTTP(), origin, webdiff.Options{MaxRequests: budget, Rate: float64(cfg.Rate)})
	if err != nil {
		return nil, err
	}
	p.AddGap(webdiff.GapScopeFiltered, res.filtered)
	defer func() {
		res.requests, res.stopped, res.gaps = p.Requests(), p.Stopped(), p.Gaps()
		if res.requests == 0 {
			if res.gaps == nil {
				res.gaps = map[string]int{}
			}
			res.gaps[toolrun.GapNoCandidates]++
		}
	}()
	if len(allowed) == 0 {
		return res, nil
	}
	v, err := p.Canary(ctx)
	res.edge = v
	if err != nil && !errors.Is(err, webdiff.ErrStopped) {
		return nil, err
	}
	input := make(map[string]bool, len(allowed))
	for _, c := range allowed {
		input[c] = true
	}
	seenFold := map[string]bool{}
	caseChecked := false
	for _, c := range allowed {
		if p.Stopped() != "" {
			break
		}
		if p.FoldsCase() {
			if seenFold[strings.ToLower(c)] {
				continue
			}
		}
		seenFold[strings.ToLower(c)] = true
		r, err := p.Check(ctx, c)
		res.checked++
		if errors.Is(err, webdiff.ErrStopped) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			continue
		}
		if r.Hit == nil {
			continue
		}
		// The differ reports the path it was given; anything else is never
		// emitted (a tool never adds a path).
		if !input[r.Hit.Path] {
			continue
		}
		if err := ctx.Emit().Endpoint(webdiff.Endpoint(origin, r.Hit)); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return res, err
			}
			ctx.Log().Warn("webguess: a record was refused", "error", err.Error())
			continue
		}
		res.hits++
		if !caseChecked {
			caseChecked = true
			if _, err := p.CaseInsensitive(ctx, r.Hit); err != nil && !errors.Is(err, webdiff.ErrStopped) && ctx.Err() != nil {
				return res, ctx.Err()
			}
		}
	}
	return res, nil
}

// allowedCandidate reports whether a candidate may be requested: inside the
// job's web scope (as the forwarder reads it), outside the scan's excluded
// paths, and not naming a state-changing action.
func allowedCandidate(ws *webscope.Scope, hosts, exclude []string, base *url.URL, c string) bool {
	if webpath.Destructive(c) {
		return false
	}
	// A guess holds printable ASCII only and no escaped percent sign:
	// servers fold other letters (fullwidth, long s) and decode twice in
	// different ways, so such a guess could reach an excluded path.
	if webpath.CheckCandidate(c) != nil {
		return false
	}
	u, err := base.Parse(c)
	if err != nil || u.Host != base.Host || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if ws.Allows("GET", u, hosts) != nil {
		return false
	}
	clean, err := webpath.CleanPath(u.EscapedPath())
	if err != nil {
		return false
	}
	_, denied := webpath.Denied(clean, exclude)
	return !denied
}

// gap is the origin's coverage gap: the origin as its host, the main reason,
// and every reason with its count as the detail. None when nothing limited
// the origin.
func (r *originResult) gap() (adapt.Gap, bool) {
	if len(r.gaps) == 0 {
		return adapt.Gap{}, false
	}
	reasons := make([]string, 0, len(r.gaps))
	for k := range r.gaps {
		reasons = append(reasons, k)
	}
	sort.Strings(reasons)
	main := reasons[0]
	for _, g := range gapOrder {
		if r.gaps[g] > 0 {
			main = g
			break
		}
	}
	parts := make([]string, 0, len(reasons))
	for _, k := range reasons {
		parts = append(parts, fmt.Sprintf("%s=%d", k, r.gaps[k]))
	}
	g := adapt.Gap{Host: r.origin, Reason: main, Detail: clip(strings.Join(parts, " "), 256)}
	if main == webdiff.GapEdgeProtected && r.edge.State.Stops() {
		g.Edge, g.Vendor = string(r.edge.State), clip(r.edge.Vendor, 32)
	}
	return g, true
}

// originOf is the origin of a target: scheme, host and port of an http(s)
// URL, nothing else.
func originOf(v string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", errors.New("not an http(s) origin")
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

// readCandidates reads the composed list: one relative path per line
// (wordlist web-paths entries), each made absolute, without repeats. An
// entry with a query or fragment is not a path candidate and is left out.
func readCandidates(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // the composed list in the task's own directory (tool host)
	if err != nil {
		return nil, errors.New("cannot be opened")
	}
	defer func() { _ = f.Close() }()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 8192)
	for sc.Scan() && len(out) < maxCandidates {
		e := strings.TrimSpace(sc.Text())
		if e == "" || strings.ContainsAny(e, "?#") {
			continue
		}
		p := "/" + strings.TrimLeft(e, "/")
		if p == "/" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, errors.New("cannot be read")
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
