package recon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sensor/internal/reachobs"
)

// reachBatch is a batch tool that reads reach outcomes (naabu).
type reachBatch struct{ fakeBatch }

func (r *reachBatch) ReachObservations(string, *core.ReconResult) []reachobs.Obs { return nil }

func (r *reachBatch) ScanBatch(ctx context.Context, targets []string, opts *core.ReconOptions, b time.Duration, seen func(string)) (map[string]*core.ReconResult, error) {
	return r.fakeBatch.ScanBatch(ctx, targets, opts, b, seen)
}

// The incident: a host discovery run of naabu over address ranges exited
// with a fatal line. Its text was read as every range's reach outcome, so
// the step failed TARGET_UNREACHABLE although nothing was probed. A run
// failure now records no reach outcome and fails the job with the cause on
// the sensor's side.
func TestRunFailureIsNotEveryTargetUnreachable(t *testing.T) {
	ranges := []string{"10.20.0.0/24", "10.20.1.0/24", "10.20.2.0/24"}
	names := []string{"a.example.com", "b.example.com"}
	cases := []struct {
		name    string
		targets []string
		stderr  string
		class   core.FailureClass
		cause   string
	}{
		{"local refusal", ranges, "naabu exited 1: [FTL] Could not run enumeration: dial tcp 10.20.0.1:443: socket: operation not permitted",
			core.FailureSensorNetwork, causeLocalRefused},
		{"no route on the sensor", ranges, "naabu exited 1: [FTL] connect: network is unreachable",
			core.FailureSensorNetwork, causeNoRoute},
		{"names, resolver down", names, "naabu exited 1: [FTL] Could not create runner: no valid ipv4 or ipv6 targets were found",
			core.FailureDNSResolver, causeSensorDNS},
		{"ranges, nothing to scan", ranges, "naabu exited 1: [FTL] Could not create runner: no valid ipv4 or ipv6 targets were found",
			core.FailureUnknown, causeNoAddress},
		{"other", ranges, "naabu exited 2: flag provided but not defined", core.FailureUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &reachBatch{fakeBatch{fakeRecon: fakeRecon{name: "naabu", typ: core.ReconTypePort}, batchErr: errors.New(c.stderr)}}
			_, obs, err := NewScanner(f).scanTargets(context.Background(), c.targets, nil, nil)
			if !errors.Is(err, ErrToolFailed) {
				t.Fatalf("err = %v, want the job failed as a tool run", err)
			}
			for _, o := range obs {
				if o.Class.Unreached() {
					t.Fatalf("a run failure was recorded as %s toward %s", o.Class, o.Target)
				}
			}
			f2 := core.ClassifyFailure(core.FailureInput{Err: err, Tool: "naabu"})
			if f2 == nil || f2.Class != c.class {
				t.Fatalf("failure class = %+v, want %s", f2, c.class)
			}
			if f2.ErrorCode() == "TARGET_UNREACHABLE" {
				t.Fatal("a run failure reported TARGET_UNREACHABLE")
			}
			if c.cause != "" && !strings.Contains(err.Error(), c.cause) {
				t.Fatalf("error %q does not name the cause %q", err, c.cause)
			}
		})
	}
}

// Through the tool host (the tool child), a sensor network or DNS failure
// ends the task as temporary with the cause; any other run failure stays the
// tool's.
func TestRunFailureError(t *testing.T) {
	var te *tool.Error
	err := runFailureError(classifyRun(errors.New("naabu: socket: operation not permitted"), []string{"192.0.2.0/24"}))
	if !errors.As(err, &te) || te.Class != tool.Transient || !strings.Contains(te.Detail, "not the targets") {
		t.Fatalf("sensor network failure = %+v", err)
	}
	err = runFailureError(classifyRun(errors.New("naabu: bad flag"), []string{"192.0.2.0/24"}))
	if !errors.As(err, &te) || te.Class == tool.Transient || te.Class == tool.TargetUnreachable {
		t.Fatalf("tool failure = %+v", err)
	}
}

// Only a list with a host name can fail on DNS.
func TestHasName(t *testing.T) {
	for in, want := range map[string]bool{
		"192.0.2.7": false, "192.0.2.0/24": false, "192.0.2.1-192.0.2.9": false, "2001:db8::/120": false,
		"a.example.com": true,
	} {
		if got := hasName([]string{in}); got != want {
			t.Errorf("hasName(%q) = %v, want %v", in, got, want)
		}
	}
}
