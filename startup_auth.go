package main

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// exitAuthRejected is the exit code of a one-shot run whose API key the
// platform rejects (EX_CONFIG from sysexits.h): the configuration is wrong
// and running again will not help until it is fixed.
const exitAuthRejected = 78

// waitForAcceptedKey is the daemon's connection check. It sends the first
// heartbeat (first, normally BaseSensor.FirstHeartbeat) and, while the
// platform rejects the key, waits the backoff the heartbeat returned and tries
// again: the daemon stays up instead of exiting into a restart loop, and picks
// up a re-activated sensor by itself. The SDK's AuthGate logs every attempt.
// A network failure does not block start-up (the heartbeat loop keeps
// retrying). It returns false when ctx is cancelled while waiting.
func waitForAcceptedKey(ctx context.Context, first func(context.Context) (time.Duration, error), wait func(context.Context, time.Duration) bool) bool {
	for {
		next, err := first(ctx)
		if core.AuthFailureStatus(err) == 0 {
			if err == nil {
				fmt.Println("✓ Connected to API")
			}
			return true
		}
		if !wait(ctx, next) {
			return false
		}
	}
}

// sleepCtx waits d, or returns false at once when ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
