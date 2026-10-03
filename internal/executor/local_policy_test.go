package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// innerRecorder fails the test if any command reaches it.
type innerRecorder struct{ calls int }

func (r *innerRecorder) Execute(context.Context, *core.Command) (*core.CommandExecutionResult, error) {
	r.calls++
	return &core.CommandExecutionResult{}, nil
}

func policyForTest(t *testing.T, doc string, dns map[string][]string) *core.LocalPolicy {
	t.Helper()
	lp, err := core.ParseLocalPolicy([]byte(doc), core.LocalPolicyOptions{
		LookupEnv: func(string) (string, bool) { return "", false },
		LookupIP: func(_ context.Context, host string) ([]net.IP, error) {
			var ips []net.IP
			for _, a := range dns[host] {
				ips = append(ips, net.ParseIP(a))
			}
			if len(ips) == 0 {
				return nil, errors.New("no such host")
			}
			return ips, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

func validateCmd(t *testing.T, kind, address string) *core.Command {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"executor_kind": kind, "finding_id": "f1",
		"target": map[string]any{"address": address}, "timeout_seconds": 5})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "v1", Type: validateCommandType, Payload: raw}
}

// A validate job outside the local policy fails with the policy's reason
// before any probe: a denied range, a name that resolves into it, a port the
// policy does not list.
func TestValidate_LocalPolicyRefuses(t *testing.T) {
	lp := policyForTest(t, `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["203.0.113.0/24", "*.corp.example.com"]
  deny: ["203.0.113.128/25"]
ports: {allow: "443"}
`, map[string][]string{"db.corp.example.com": {"203.0.113.200"}, "www.corp.example.com": {"203.0.113.10"}})
	inner := &innerRecorder{}
	e := NewValidatingCommandExecutor(inner, false)
	e.SetLocalPolicy(lp)
	for address, rule := range map[string]string{
		"203.0.113.200:443":               "targets.deny",
		"https://db.corp.example.com/":    "targets.deny",
		"198.51.100.1:443":                "targets.allow",
		"www.corp.example.com:22":         "ports.allow",
		"http://www.corp.example.com/":    "ports.allow",
		"https://169.254.169.254/latest/": "builtin",
	} {
		_, err := e.Execute(context.Background(), validateCmd(t, "safe_check", address))
		var pe *core.LocalPolicyError
		if !errors.As(err, &pe) || pe.Rule != rule || !strings.HasPrefix(err.Error(), "refused by local policy: "+rule) {
			t.Errorf("%s: err %v, want rule %s", address, err, rule)
		}
	}
	if inner.calls != 0 {
		t.Fatal("a validate job reached the inner executor")
	}
}

// The safe-check connects through the policy's guarded dialer: a connection
// the policy refuses is never made, even to a listener that is up.
func TestSafeCheck_DialsThroughLocalPolicy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	lp := policyForTest(t, "apiVersion: openctem.io/sensor-policy/v1\nports: {allow: \"443\"}\n", nil)

	outcome, _, ev := probeReachability(context.Background(), []string{ln.Addr().String()}, 2*time.Second, nil, lp.DialContext(nil))
	if outcome == "detected" {
		t.Fatalf("outcome detected through a refused dial: %v", ev)
	}
	select {
	case <-accepted:
		t.Fatal("the guarded dialer connected to a refused address")
	case <-time.After(200 * time.Millisecond):
	}
	// Without the policy's dialer the same probe connects: the refusal above
	// is the policy's.
	if outcome, _, _ := probeReachability(context.Background(), []string{ln.Addr().String()}, 2*time.Second, nil, nil); outcome != "detected" {
		t.Fatalf("plain dial outcome %s", outcome)
	}
}
