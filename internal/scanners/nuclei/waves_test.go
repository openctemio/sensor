package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/politeness"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// gatedNuclei is a fake nuclei that logs each run's target list
// ("run <n>: t1 t2 ...") and then waits for the file go-<n> before it
// prints one result per target and exits.
func gatedNuclei(t *testing.T) (bin, dir string) { return gatedNucleiFailing(t, 0) }

// gatedNucleiFailing is gatedNuclei whose run failRun (> 0) fails at once:
// a fatal line and no output.
func gatedNucleiFailing(t *testing.T, failRun int) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "nuclei")
	script := `#!/bin/sh
dir="` + dir + `"
targets=""
while [ $# -gt 0 ]; do
  case "$1" in
    -u) targets="$2";;
    -l) targets="$(cat "$2")";;
  esac
  shift
done
n=$(ls "$dir"/run-* 2>/dev/null | wc -l)
n=$((n+1))
echo $targets > "$dir/run-$n"
if [ $n -eq ` + fmt.Sprint(failRun) + ` ]; then echo "[FTL] boom" >&2; exit 3; fi
i=0
while [ ! -f "$dir/go-$n" ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done
for t in $targets; do
  printf '{"template-id":"tpl-1","info":{"name":"T","severity":"high","tags":["cve"],"description":"d"},"host":"%s","matched-at":"%s/x","type":"http","ip":"%s"}\n' "$t" "$t" "$t"
done
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

// The live shape (2026-10-14): a chunk of 23 targets over 21 hosts, two
// hosts named twice (bare and address:port). Out of process nuclei runs in
// TargetWaves waves of whole hosts, and every target of a wave is done
// (its hosts released) before the next wave starts.
func TestWaves_ReleaseHostsBeforeTheNextWave(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	bin, dir := gatedNuclei(t)
	var targets []string
	for i := 1; i <= 21; i++ {
		targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
	}
	targets = append(targets, "203.0.113.3:8443", "203.0.113.9:443")
	p := core.NewProgress(0)
	p.SetTargets(targets)
	ctx := core.WithProgress(context.Background(), p)

	type result struct {
		res *core.ScanResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := scanner(bin).ScanTargets(ctx, targets, nil)
		done <- result{res, err}
	}()
	waitFor := func(path string) string {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(path); err == nil {
				return strings.TrimSpace(string(b))
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s never appeared", path)
		return ""
	}
	var waves [][]string
	settled := 0
	for n := 1; n <= TargetWaves; n++ {
		wave := strings.Fields(waitFor(filepath.Join(dir, fmt.Sprintf("run-%d", n))))
		// The earlier waves are done while this one runs: their hosts
		// are free for the next tool already.
		if got := p.Snapshot().Done; got != settled {
			t.Fatalf("wave %d started with %d targets done, want %d", n, got, settled)
		}
		waves = append(waves, wave)
		settled += len(wave)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("go-%d", n)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("run-%d", TargetWaves+1))); err == nil {
		t.Fatal("more runs than waves")
	}
	var all []string
	for a, w := range waves {
		all = append(all, w...)
		for b := a + 1; b < len(waves); b++ {
			conf := politeness.Conflicts(politeness.Keys(w, ""))
			for _, k := range politeness.Keys(waves[b], "") {
				if slices.Contains(conf, k) {
					t.Fatalf("waves %d and %d share host %s", a+1, b+1, k)
				}
			}
		}
	}
	slices.Sort(all)
	want := slices.Clone(targets)
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Fatalf("waves ran %q", all)
	}
	// Every wave's findings arrived, each on its own host's asset (the
	// waves' report-local asset ids do not collide).
	var rep struct {
		Assets []struct {
			ID, Value string
		}
		Findings []struct {
			AssetRef string `json:"asset_ref"`
			Message  string
		}
	}
	if err := json.Unmarshal(parse(t, r.res.RawOutput), &rep); err != nil {
		t.Fatal(err)
	}
	value := map[string]string{}
	for _, a := range rep.Assets {
		value[a.ID] = a.Value
	}
	if len(rep.Findings) != len(targets) {
		t.Fatalf("%d findings, want %d", len(rep.Findings), len(targets))
	}
	for _, f := range rep.Findings {
		host := politeness.HostOf(strings.TrimSuffix(strings.TrimPrefix(f.Message, "T at "), "/x"))
		if v := value[f.AssetRef]; v != host {
			t.Fatalf("finding %q is on asset %q (%s)", f.Message, v, f.AssetRef)
		}
	}
}

// A wave that fails after an earlier one ended: the earlier wave keeps its
// findings and stays done, the failed and later waves' targets are left
// unfinished (the platform sends them again), and no finding of a host
// that did not finish is delivered.
func TestWaves_LaterWaveFails(t *testing.T) {
	t.Setenv(toolrun.EnvRuntime, "")
	bin, dir := gatedNucleiFailing(t, 2)
	if err := os.WriteFile(filepath.Join(dir, "go-1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	targets := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
	p := core.NewProgress(0)
	p.SetTargets(targets)
	res, err := scanner(bin).ScanTargets(core.WithProgress(context.Background(), p), targets, nil)
	if err != nil {
		t.Fatalf("a partial run is not an error: %v", err)
	}
	b, rerr := os.ReadFile(filepath.Join(dir, "run-1"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	first := strings.Fields(string(b))
	if got := p.Snapshot().Done; got != len(first) {
		t.Fatalf("%d targets done, want the first wave's %d", got, len(first))
	}
	if _, err := os.Stat(filepath.Join(dir, "run-3")); err == nil {
		t.Fatal("a wave ran after the failed one")
	}
	out := string(parse(t, res.RawOutput))
	for _, tg := range targets {
		if got, want := strings.Contains(out, "T at "+tg+"/x"), slices.Contains(first, tg); got != want {
			t.Fatalf("finding for %s delivered: %v, want %v", tg, got, want)
		}
	}
}
