package handler

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ctxPusher records the context each push was made with.
type ctxPusher struct{ ctxs []context.Context }

func (p *ctxPusher) PushFindings(ctx context.Context, _ *ctis.Report) (*core.PushResult, error) {
	p.ctxs = append(p.ctxs, ctx)
	return &core.PushResult{Success: true}, nil
}

func (p *ctxPusher) PushAssets(context.Context, *ctis.Report) (*core.PushResult, error) {
	return &core.PushResult{Success: true}, nil
}
func (p *ctxPusher) SendHeartbeat(context.Context, *core.SensorStatus) error { return nil }
func (p *ctxPusher) TestConnection(context.Context) error                    { return nil }

// The push is made with the run's context, so a command id on it reaches the
// SDK (which sends it with the results; without it the platform treats them as
// unsolicited) and a canceled run stops the push. It used to be
// context.Background().
func TestHandleFindings_PushesWithRunContext(t *testing.T) {
	p := &ctxPusher{}
	h := NewRemoteHandler(&RemoteHandlerConfig{Pusher: p})
	report := &ctis.Report{Findings: []ctis.Finding{findingAt("sqli", "app.go", 5)}}

	ctx := core.WithCommandID(context.Background(), "cmd-42")
	if err := h.HandleFindings(HandleFindingsParams{Ctx: ctx, Report: report}); err != nil {
		t.Fatal(err)
	}
	if err := h.HandleFindings(HandleFindingsParams{Report: report}); err != nil {
		t.Fatal(err)
	}
	if len(p.ctxs) != 2 {
		t.Fatalf("pushes = %d, want 2", len(p.ctxs))
	}
	if got := core.CommandIDFromContext(p.ctxs[0]); got != "cmd-42" {
		t.Errorf("command id on the push = %q, want cmd-42", got)
	}
	if p.ctxs[1] == nil || core.CommandIDFromContext(p.ctxs[1]) != "" {
		t.Error("no Ctx: want a non-nil context with no command")
	}
}
