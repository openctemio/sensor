package tenablesc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// outcomePayload names targets as a platform could spell them: a range
// that is not on its boundary, a host name in mixed case, an address the
// scan lists and one it does not.
func outcomePayload() map[string]any {
	p := scanPayload()
	p["targets"] = []string{"10.20.0.5/28", "10.20.0.16", "App01.corp.example", "10.20.0.200"}
	return p
}

func outcomeCtx() (context.Context, *core.Progress, *reach.Recorder) {
	prog := core.NewProgress(0)
	rec := reach.NewRecorder()
	return reach.WithRecorder(core.WithProgress(context.Background(), prog), rec), prog, rec
}

func outcomeStates(res *core.CommandExecutionResult) map[string]string {
	out := map[string]string{}
	for _, o := range res.TargetOutcomes {
		out[o.Target] = string(o.State) + ":" + string(o.Class)
	}
	return out
}

func TestScan_TargetOutcomes_CompletedScan(t *testing.T) {
	_, _, e, _ := newScanFixture(t, running, importing, done)
	ctx, prog, rec := outcomeCtx()
	res, err := e.Execute(ctx, scanCmd(t, outcomePayload()))
	if err != nil {
		t.Fatal(err)
	}
	got := outcomeStates(res)
	want := map[string]string{
		"10.20.0.5/28":       "done:",                   // 10.20.0.15 is inside, named as the payload spelled it
		"10.20.0.16":         "done:",                   // has findings
		"App01.corp.example": "done:",                   // the scan lists the host by its DNS name
		"10.20.0.200":        "failed:" + "unreachable", // a completed scan that does not list it: no reply
	}
	if len(got) != len(want) {
		t.Fatalf("outcomes %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("outcome of %s = %q, want %q (all %v)", k, got[k], v, got)
		}
	}
	md := res.Metadata
	if md["assessed_targets"] != 3 || md["unreachable_targets"] != 1 || md["unfinished_targets"] != 0 || md["resumed"] != false {
		t.Fatalf("metadata %v", md)
	}
	snap := prog.Snapshot()
	if snap.Total != 4 || snap.Done != 4 {
		t.Fatalf("progress %+v, want every target settled", snap)
	}
	if snap.Records == 0 {
		t.Fatal("no liveness recorded from the scan's completed checks")
	}
	r := rec.Report()
	if r.Reached != 3 || r.Unreached != 1 || len(r.UnreachedList) != 1 || r.UnreachedList[0].Target != "10.20.0.200" {
		t.Fatalf("reach %+v", r)
	}
}

func TestScan_TargetOutcomes_PartialScanLeavesUnlistedUnfinished(t *testing.T) {
	_, _, e, _ := newScanFixture(t, map[string]string{"status": "Partial", "import": "Finished"})
	ctx, prog, rec := outcomeCtx()
	res, err := e.Execute(ctx, scanCmd(t, outcomePayload()))
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomeStates(res)["10.20.0.200"]; got != "unfinished:" {
		t.Fatalf("an unlisted target of a partial scan is %q, want unfinished (never 'no reply')", got)
	}
	if snap := prog.Snapshot(); snap.Done != 3 {
		t.Fatalf("progress %+v: the unfinished target must not count as done", snap)
	}
	if r := rec.Report(); r.Unreached != 0 {
		t.Fatalf("reach %+v: an unfinished target is not unreached", r)
	}
}

func TestScan_TargetOutcomes_NoResultsMeansNoReply(t *testing.T) {
	_, _, e, p := newScanFixture(t, map[string]string{"status": "Completed", "import": "No Results"})
	res, err := e.Execute(context.Background(), scanCmd(t, outcomePayload()))
	if err != nil {
		t.Fatal(err)
	}
	for target, st := range outcomeStates(res) {
		if st != "failed:unreachable" {
			t.Fatalf("%s = %q, want failed:unreachable", target, st)
		}
	}
	if len(p.reports) != 0 {
		t.Fatalf("%d reports pushed for a scan with no results", len(p.reports))
	}
}

func TestScan_TimedOutTargetsAreUnfinished(t *testing.T) {
	_, _, e, _ := newScanFixture(t, running)
	pl := outcomePayload()
	pl["max_scan_seconds"] = 600
	res, err := e.Execute(context.Background(), scanCmd(t, pl))
	if err != nil {
		t.Fatal(err)
	}
	for target, st := range outcomeStates(res) {
		if st != "unfinished:" {
			t.Fatalf("%s = %q after a timeout without import, want unfinished", target, st)
		}
	}
}

func TestScan_ImportBlockedByLicenceFails(t *testing.T) {
	_, sim, e, p := newScanFixture(t, running, map[string]string{"status": "Completed", "import": "Blocked"})
	_, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
	if !errors.Is(err, ErrImportRefused) {
		t.Fatalf("err %v, want ErrImportRefused", err)
	}
	if !strings.Contains(err.Error(), "licence") || !strings.Contains(err.Error(), "licensed 2048, active 1530") {
		t.Fatalf("error does not explain the licence: %v", err)
	}
	if len(p.reports) != 0 {
		t.Fatalf("%d reports pushed for a blocked import", len(p.reports))
	}
	if len(sim.deletes) != 1 || sim.deletes[0] != "42" {
		t.Fatalf("deletes %v: the definition is still cleaned up", sim.deletes)
	}
}

func TestScan_ErrorStatusWithoutImportFails(t *testing.T) {
	_, _, e, _ := newScanFixture(t, map[string]string{"status": "Error", "import": "No Results"})
	if _, err := e.Execute(context.Background(), scanCmd(t, scanPayload())); err == nil || !strings.Contains(err.Error(), `"Error"`) {
		t.Fatalf("err %v", err)
	}
}

func TestScan_ResumesTheScanResultThisCommandLaunched(t *testing.T) {
	_, sim, e, p := newScanFixture(t, running, done)
	sim.results = []map[string]any{
		{"id": "770", "name": "openctem-cmd-scan-1", "status": "Completed", "repository": map[string]any{"id": "9"}}, // other repository: never taken
		{"id": "776", "name": "openctem-cmd-scan-2", "status": "Running", "repository": map[string]any{"id": "5"}},   // another command
		{"id": "777", "name": "openctem-cmd-scan-1", "status": "Running", "importStatus": "No Results", "repository": map[string]any{"id": "5"}},
	}
	sim.defs = []map[string]any{{"id": "42", "name": "openctem-cmd-scan-1"}, {"id": "41", "name": "someone-elses-scan"}}
	res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 0 || len(sim.launches) != 0 {
		t.Fatalf("created %d launched %v: a restarted command must follow its own scan", len(sim.created), sim.launches)
	}
	if res.Metadata["resumed"] != true || res.Metadata["scan_result_id"] != "777" || len(p.reports) == 0 {
		t.Fatalf("metadata %v reports %d", res.Metadata, len(p.reports))
	}
	if len(sim.deletes) != 1 || sim.deletes[0] != "42" {
		t.Fatalf("deletes %v: only this command's definition", sim.deletes)
	}
}

func TestScan_LaunchesADefinitionCreatedButNeverLaunched(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	sim.results = []map[string]any{}
	sim.defs = []map[string]any{{"id": "42", "name": "openctem-cmd-scan-1"}}
	res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 0 || len(sim.launches) != 1 || res.Metadata["resumed"] != true {
		t.Fatalf("created %d launches %v md %v", len(sim.created), sim.launches, res.Metadata)
	}
}

func TestScan_NothingToResumeLaunchesOnce(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	sim.results = []map[string]any{{"id": "9", "name": "openctem-cmd-scan-10", "repository": map[string]any{"id": "5"}}}
	sim.defs = []map[string]any{}
	res, err := e.Execute(context.Background(), scanCmd(t, scanPayload()))
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 1 || len(sim.launches) != 1 || res.Metadata["resumed"] != false || sim.lookups != 2 {
		t.Fatalf("created %d launches %v lookups %d md %v", len(sim.created), sim.launches, sim.lookups, res.Metadata)
	}
}

func TestAssessedHosts_Covers(t *testing.T) {
	h := newAssessedHosts()
	h.add("10.0.0.7", "Web.Example.")
	h.add("not-an-ip", "bad name!")
	h.add("::ffff:10.0.1.1", "")
	for target, want := range map[string]bool{
		"10.0.0.7": true, "10.0.0.0/29": true, "10.0.0.8/29": false, "web.example": true,
		"10.0.1.1": true, "10.0.0.8": false, "other.example": false, "bad name!": false,
	} {
		if got := h.covers(target); got != want {
			t.Fatalf("covers(%q) = %v, want %v", target, got, want)
		}
	}
	var nilHosts *assessedHosts
	nilHosts.add("10.0.0.1", "")
	if nilHosts.covers("10.0.0.1") {
		t.Fatal("nil covers")
	}
}

func TestTargetOutcomes_AreValidCTIS(t *testing.T) {
	job := &scanJob{targets: []string{"10.0.0.0/30", "a.example"}, raw: map[string]string{"10.0.0.0/30": "10.0.0.1/30"}}
	h := newAssessedHosts()
	h.add("10.0.0.2", "")
	for _, complete := range []bool{true, false} {
		outs, _ := targetOutcomes(job, h, complete, nil)
		norm := outcome.Normalize(outs, []string{"10.0.0.1/30", "a.example"})
		for i := range outs {
			if !outs[i].Valid() || norm[i] != outs[i] {
				t.Fatalf("complete=%v: outcome %+v not valid CTIS or not the payload spelling", complete, outs[i])
			}
		}
	}
}

// The payload exactly as the platform builds it for a scan run (captured
// from a scratch end-to-end run): run and step keys and per-host politeness
// keys included. Strict decoding refused host_keys before, so every scan
// launched from OpenCTEM failed at admission.
func TestScan_AcceptsThePlatformPayload(t *testing.T) {
	_, sim, e, _ := newScanFixture(t, done)
	raw := `{"run_id": "01a13b37-7517-7c9c-8b98-adadf47d053e", "scan_id": "01a13b37-69e5-74b5-b2c6-96a6756fa159",
		"scanner": "tenable_sc", "targets": ["10.20.0.15", "10.20.0.16"], "zone_id": 2, "instance": "sc-test",
		"step_key": "quick_scan", "host_keys": ["10.20.0.15", "10.20.0.16", "in:10.20.0.0/24"], "policy_id": 1000003,
		"scan_run_id": "01a13b37-7517-7c9c-8b98-adadf47d053e", "min_severity": 1, "repository_id": 5,
		"integration_id": "01a13b32-cc3c-77b7-ac6e-fa7b36c2028d", "max_scan_seconds": 1800,
		"scan_run_step_id": "01a13b37-751d-78ff-9b63-1c6e951939b0"}`
	cmd := &core.Command{ID: "cmd-scan-1", Type: CommandTypeScan, Payload: []byte(raw)}
	if _, err := e.Execute(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if len(sim.created) != 1 || sim.created[0]["ipList"] != "10.20.0.15,10.20.0.16" {
		t.Fatalf("created %v", sim.created)
	}
	// Bookkeeping never reaches Tenable.sc, and an unknown key is still refused.
	bad := &core.Command{ID: "cmd-scan-2", Type: CommandTypeScan, Payload: []byte(strings.Replace(raw, `"zone_id"`, `"url": "https://x", "zone_id"`, 1))}
	if _, err := e.Execute(context.Background(), bad); !errors.Is(err, ErrRefused) {
		t.Fatalf("unknown key: %v", err)
	}
}
