package targetguard

import (
	"context"
	"testing"
)

func TestGuard_AllowsPrivateRanges(t *testing.T) {
	g := New(0, 0)
	ctx := context.Background()
	// Scanning the internal corporate network is the runner's whole purpose.
	allowed := []string{"10.0.0.1", "192.168.1.5", "172.16.0.10", "10.0.0.0/24", "8.8.8.8"}
	for _, target := range allowed {
		if err := g.validateTarget(ctx, target); err != nil {
			t.Errorf("target %q should be allowed, got: %v", target, err)
		}
	}
}

func TestGuard_BlocksDangerousRanges(t *testing.T) {
	g := New(0, 0)
	ctx := context.Background()
	blocked := []string{
		"169.254.169.254", // cloud metadata
		"169.254.0.0/16",  // link-local range
		"127.0.0.1",       // loopback
		"127.0.0.0/8",     // loopback range
		"::1",             // IPv6 loopback
		"0.0.0.0",         // unspecified
		"100.64.1.1",      // CGNAT
		"224.0.0.1",       // multicast
		"255.255.255.255", // broadcast
		"localhost",       // alias
		"metadata",        // alias
		"metadata.google.internal",
	}
	for _, target := range blocked {
		if err := g.validateTarget(ctx, target); err == nil {
			t.Errorf("target %q must be blocked", target)
		}
	}
}

func TestGuard_BoundsCIDRSize(t *testing.T) {
	g := New(0, 0) // default max = /16 (65536)
	ctx := context.Background()
	if err := g.validateTarget(ctx, "10.0.0.0/8"); err == nil {
		t.Fatal("a /8 exceeds the default /16 bound and must be rejected")
	}
	if err := g.validateTarget(ctx, "0.0.0.0/0"); err == nil {
		t.Fatal("0.0.0.0/0 must be rejected (oversized + overlaps blocked ranges)")
	}
	// Exactly /16 is allowed.
	if err := g.validateTarget(ctx, "10.1.0.0/16"); err != nil {
		t.Fatalf("a /16 should be within bound: %v", err)
	}
}

func TestGuard_PortStrippedFromTarget(t *testing.T) {
	g := New(0, 0)
	if err := g.validateTarget(context.Background(), "127.0.0.1:8834"); err == nil {
		t.Fatal("loopback with a port must still be blocked")
	}
}

func TestGuard_FailClosedOnDNSFailure(t *testing.T) {
	g := New(0, 0)
	// .invalid is reserved (RFC 2606) and never resolves → must fail closed.
	if err := g.validateTarget(context.Background(), "nope.invalid"); err == nil {
		t.Fatal("unresolvable hostname must fail closed")
	}
}

func TestGuard_ValidateTargets_RejectsWholeSetOnOneBad(t *testing.T) {
	g := New(0, 0)
	ctx := context.Background()
	err := g.ValidateTargets(ctx, []string{"10.0.0.1", "10.0.0.2", "169.254.169.254"})
	if err == nil {
		t.Fatal("one blocked target must fail the entire batch (fail-loud)")
	}
}

func TestGuard_ValidateTargets_AllowsCleanBatch(t *testing.T) {
	g := New(0, 0)
	if err := g.ValidateTargets(context.Background(), []string{"10.0.0.0/24", "192.168.1.1"}); err != nil {
		t.Fatalf("clean batch should pass: %v", err)
	}
}

func TestGuard_ValidateTargets_BoundsCount(t *testing.T) {
	g := New(0, 2)
	if err := g.ValidateTargets(context.Background(), []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}); err == nil {
		t.Fatal("a target list larger than maxTargets must be rejected")
	}
}

func TestGuard_ValidateTargets_Empty(t *testing.T) {
	g := New(0, 0)
	if err := g.ValidateTargets(context.Background(), nil); err == nil {
		t.Fatal("empty target set must error")
	}
}
