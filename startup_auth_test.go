package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type statusErr struct{ code int }

func (e *statusErr) Error() string       { return fmt.Sprintf("http %d", e.code) }
func (e *statusErr) HTTPStatusCode() int { return e.code }

func TestWaitForAcceptedKey_RetriesWhileRejected(t *testing.T) {
	results := []error{&statusErr{401}, fmt.Errorf("wrapped: %w", &statusErr{403}), nil}
	delays := []time.Duration{30 * time.Second, time.Minute, 30 * time.Second}
	calls := 0
	first := func(context.Context) (time.Duration, error) {
		d, err := delays[calls], results[calls]
		calls++
		return d, err
	}
	var waited []time.Duration
	wait := func(_ context.Context, d time.Duration) bool { waited = append(waited, d); return true }

	if !waitForAcceptedKey(context.Background(), first, wait) {
		t.Fatal("must return true once the key is accepted")
	}
	if calls != 3 {
		t.Fatalf("heartbeats %d, want 3 (2 rejected + 1 accepted)", calls)
	}
	if len(waited) != 2 || waited[0] != 30*time.Second || waited[1] != time.Minute {
		t.Fatalf("waited %v, want the backoff the heartbeat returned [30s 1m]", waited)
	}
}

func TestWaitForAcceptedKey_NetworkFailureDoesNotBlockStart(t *testing.T) {
	calls := 0
	first := func(context.Context) (time.Duration, error) {
		calls++
		return time.Minute, errors.New("dial tcp: connection refused")
	}
	wait := func(context.Context, time.Duration) bool { t.Fatal("must not wait on a network failure"); return false }
	if !waitForAcceptedKey(context.Background(), first, wait) || calls != 1 {
		t.Fatalf("network failure: want one heartbeat then start, got %d", calls)
	}
}

func TestWaitForAcceptedKey_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	first := func(context.Context) (time.Duration, error) { return time.Hour, &statusErr{401} }
	if waitForAcceptedKey(ctx, first, sleepCtx) {
		t.Fatal("a cancelled wait must return false")
	}
}

func TestExitAuthRejectedIsEXConfig(t *testing.T) {
	if exitAuthRejected != 78 {
		t.Errorf("exit code %d, want 78 (EX_CONFIG)", exitAuthRejected)
	}
}
