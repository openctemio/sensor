package executor

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// captureHandler records the messages logged through it.
type captureHandler struct {
	mu   *sync.Mutex
	msgs *[]string
}

func (h captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	line := r.Message
	r.Attrs(func(a slog.Attr) bool { line += " " + a.Key + "=" + a.Value.String(); return true })
	*h.msgs = append(*h.msgs, line)
	return nil
}
func (h captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h captureHandler) WithGroup(string) slog.Handler      { return h }

// A validate job writes its steps to the command's log on the platform:
// started (which executor) and finished (outcome), through the logger of
// the command its context runs for.
func TestValidatingCommandExecutor_LogsToTheCommand(t *testing.T) {
	var mu sync.Mutex
	var msgs []string
	var gotID string
	e := NewValidatingCommandExecutor(&recordingExecutor{}, false)
	e.SetCommandLogger(func(ctx context.Context) *slog.Logger {
		gotID = core.CommandIDFromContext(ctx)
		return slog.New(captureHandler{mu: &mu, msgs: &msgs})
	})
	ctx := core.WithCommandID(context.Background(), "cmd-7")
	cmd := &core.Command{ID: "cmd-7", Type: "validate", Payload: []byte(`{"target":{"address":"192.0.2.1:1"},"timeout_seconds":1}`)}
	if _, err := e.Execute(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(msgs, "\n")
	if gotID != "cmd-7" || !strings.Contains(joined, "Validation started executor=safe-check") ||
		!strings.Contains(joined, "Validation finished: ") {
		t.Fatalf("command %q lines:\n%s", gotID, joined)
	}
}
