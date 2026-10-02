package content

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// CommandExecutor handles refresh_content commands and delegates every
// other command to Inner.
type CommandExecutor struct {
	Inner   core.CommandExecutor
	Manager *Manager
	// Timeout bounds one refresh command (default 30 minutes).
	Timeout time.Duration
}

// Execute implements core.CommandExecutor.
func (e *CommandExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	if cmd == nil || cmd.Type != core.CommandTypeRefreshContent {
		if e.Inner == nil {
			return nil, fmt.Errorf("no executor for command type %q", cmdType(cmd))
		}
		return e.Inner.Execute(ctx, cmd)
	}
	start := time.Now()
	if e.Manager == nil {
		return nil, errors.New("refresh_content: content management is off on this sensor (SENSOR_CONTENT=off)")
	}
	req, err := core.ParseRefreshContentRequest(cmd.Payload)
	if err != nil {
		return nil, err
	}
	if req.Policy != nil {
		if err := e.Manager.SetPolicy(*req.Policy); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, firstDuration(e.Timeout, refreshBudget))
	defer cancel()
	results := e.Manager.Refresh(ctx, req.Content, req.Force)

	refreshed := []string{}
	unchanged := []string{}
	skipped := []string{}
	failed := map[string]string{}
	for _, r := range results {
		switch {
		case r.Err != nil:
			failed[r.Name] = shortError(r.Err)
		case r.Refreshed:
			refreshed = append(refreshed, r.Name)
		case r.Skipped:
			skipped = append(skipped, r.Name)
		default:
			unchanged = append(unchanged, r.Name)
		}
	}
	res := &core.CommandExecutionResult{
		DurationMs: time.Since(start).Milliseconds(),
		Metadata: map[string]any{
			"content":   e.Manager.Content(),
			"refreshed": refreshed,
			"unchanged": unchanged,
			"skipped":   skipped,
			"failed":    failed,
		},
	}
	if len(failed) > 0 && len(failed) == len(results)-len(skipped) {
		names := make([]string, 0, len(failed))
		for n, msg := range failed {
			names = append(names, n+": "+msg)
		}
		return res, fmt.Errorf("refresh_content failed: %s", strings.Join(names, "; "))
	}
	return res, nil
}

func cmdType(cmd *core.Command) string {
	if cmd == nil {
		return ""
	}
	return cmd.Type
}
