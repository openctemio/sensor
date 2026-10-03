package nuclei_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/mocks"
	"github.com/openctemio/sensor/internal/scanners/nuclei"
)

const jsonl = `{"template-id":"git-config","info":{"name":"Git Config File Detection","severity":"medium"},"type":"http","host":"http://203.0.113.10","matched-at":"http://203.0.113.10/.git/config","ip":"203.0.113.10","timestamp":"2026-10-01T00:00:00Z"}
{"template-id":"generic-env","info":{"name":"Generic Env File Disclosure","severity":"high"},"type":"http","host":"http://203.0.113.10","matched-at":"http://203.0.113.10/.env","ip":"203.0.113.10","timestamp":"2026-10-01T00:00:01Z"}
`

func TestReportParser(t *testing.T) {
	p := &nuclei.ReportParser{}
	if !p.CanParse([]byte(jsonl)) {
		t.Fatal("CanParse rejected nuclei JSON Lines")
	}
	report, err := p.Parse(context.Background(), []byte(jsonl), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(report.Findings))
	}
	if report.Tool == nil || report.Tool.Name != "nuclei" {
		t.Fatalf("tool = %+v, want nuclei", report.Tool)
	}
	for _, f := range report.Findings {
		if f.AssetRef == "" {
			t.Errorf("finding %q has no asset", f.Title)
		}
	}
}

func TestReportParserRejectsForeignOutput(t *testing.T) {
	p := &nuclei.ReportParser{}
	for name, data := range map[string]string{
		"sarif":             `{"version":"2.1.0","runs":[]}`,
		"gitleaks array":    `[{"RuleID":"aws-access-token"}]`,
		"json, no tpl id":   `{"host":"x"}`,
		"plain text":        "[INF] Templates loaded",
		"empty":             "",
		"leading junk line": "junk\n" + jsonl, // CanParse is strict
	} {
		if p.CanParse([]byte(data)) {
			t.Errorf("%s: CanParse = true", name)
		}
	}
	if _, err := p.Parse(context.Background(), []byte("not json\nstill not json"), nil); err == nil {
		t.Error("output with no nuclei result must be an error, not an empty report")
	}
	// A stray non-result line does not drop the real results.
	r, err := p.Parse(context.Background(), []byte("[WRN] something\n"+jsonl), nil)
	if err != nil || len(r.Findings) != 2 {
		t.Errorf("want the 2 results despite a stray line, got %v, %v", r, err)
	}
}

type fakeNuclei struct{ out string }

func (s *fakeNuclei) Name() string                                      { return "nuclei" }
func (s *fakeNuclei) Version() string                                   { return "test" }
func (s *fakeNuclei) Capabilities() []string                            { return nil }
func (s *fakeNuclei) IsInstalled(context.Context) (bool, string, error) { return true, "test", nil }
func (s *fakeNuclei) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	return &core.ScanResult{ScannerName: "nuclei", RawOutput: []byte(s.out)}, nil
}

// End to end through the command executor: a dispatched nuclei scan pushes
// every result, attributed to nuclei.
func TestExecutorPushesNucleiFindings(t *testing.T) {
	for name, out := range map[string]string{
		"one result":  strings.SplitN(jsonl, "\n", 2)[0],
		"two results": jsonl,
	} {
		t.Run(name, func(t *testing.T) {
			var pushed *ctis.Report
			pusher := &mocks.MockPusher{PushFindingsFn: func(_ context.Context, r *ctis.Report) (*core.PushResult, error) {
				pushed = r
				return &core.PushResult{Success: true}, nil
			}}
			reg := core.NewParserRegistry()
			reg.Register(&nuclei.ReportParser{})
			exec := core.NewDefaultCommandExecutor(pusher)
			exec.SetParserRegistry(reg)
			exec.AddScanner(&fakeNuclei{out: out})

			payload, _ := json.Marshal(map[string]string{"scanner": "nuclei", "target": "http://203.0.113.10"})
			res, err := exec.Execute(context.Background(), &core.Command{ID: "c", Type: "scan", Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			if pushed == nil || len(pushed.Findings) == 0 || res.FindingsCount != len(pushed.Findings) {
				t.Fatalf("pushed %v, count %d", pushed, res.FindingsCount)
			}
			if pushed.Tool.Name != "nuclei" {
				t.Fatalf("tool %q", pushed.Tool.Name)
			}
		})
	}
}
