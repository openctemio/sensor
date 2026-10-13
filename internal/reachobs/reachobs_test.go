package reachobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
)

func TestClassify_ToolMessages(t *testing.T) {
	cases := map[string]reach.Class{
		"dial tcp 10.0.0.5:443: connect: no route to host":                              reach.NoRoute,
		"dial tcp 10.0.0.5:443: connect: network is unreachable":                        reach.NoRoute,
		"dial tcp 10.0.0.5:443: connect: connection refused":                            reach.PortClosed,
		"context deadline exceeded (Client.Timeout exceeded while awaiting headers)":    reach.Timeout,
		"dial tcp 10.0.0.5:443: i/o timeout":                                            reach.Timeout,
		"no address found for host":                                                     reach.DNSFailure,
		"could not resolve host":                                                        reach.DNSFailure,
		"no valid ipv4 or ipv6 targets were found":                                      reach.DNSFailure,
		"dnsx resolved none of the 1 host(s) through resolvers 10.0.0.53 (NXDOMAIN, …)": reach.DNSFailure,
		"exited with status 2":                                                          reach.Unknown,
		"":                                                                              reach.Unknown,
	}
	for msg, want := range cases {
		if got := Classify(msg); got != want {
			t.Errorf("Classify(%q) = %q, want %q", msg, got, want)
		}
	}
}

// The detail keeps only the reason, never the address or URL the message
// carried.
func TestDetail_KeepsOnlyTheReason(t *testing.T) {
	if got := Detail("Get \"https://10.0.0.5/admin?token=x\": dial tcp 10.0.0.5:443: connect: no route to host"); got != "no route to host" {
		t.Fatalf("Detail = %q", got)
	}
	if got := Detail(strings.Repeat("é", 100)); len(got) > maxDetail || !strings.HasPrefix(got, "é") {
		t.Fatalf("Detail is not bounded on a rune boundary: %q", got)
	}
	if got := Detail("a\x00b\nc"); got != "abc" {
		t.Fatalf("control characters kept: %q", got)
	}
}

func TestFailure(t *testing.T) {
	if _, ok := Failure("t", "exited with status 1"); ok {
		t.Fatal("a message without a reach outcome made an observation")
	}
	o, ok := Failure("10.0.0.5", "connect: no route to host")
	if !ok || o.Class != reach.NoRoute || o.Target != "10.0.0.5" {
		t.Fatalf("Failure = %+v, %v", o, ok)
	}
}

func recorded(t *testing.T, targets []string, obs []Obs) (reach.Report, int) {
	t.Helper()
	rec := reach.NewRecorder()
	n := Record(reach.WithRecorder(context.Background(), rec), targets, obs)
	return rec.Report(), n
}

// Observations travel from the tool child in the report and come back
// whole; the property never stays on the report.
func TestAttachTake_RoundTripThroughJSON(t *testing.T) {
	r := ctis.NewReport()
	Attach(r, []Obs{
		{Target: "a.example", Addr: "192.0.2.1", Port: 443, Class: reach.Reached},
		{Target: "a.example", Addr: "192.0.2.1", Port: 8443, Class: reach.Reached}, // same port class: one
		{Target: "b.example", Class: reach.DNSFailure, Detail: "no answer"},
		{Target: "c.example", Class: reach.Unknown},
	})
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back ctis.Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	obs := Take(&back)
	if len(obs) != 2 {
		t.Fatalf("took %d observations, want 2 (deduplicated, unknown left out): %+v", len(obs), obs)
	}
	if obs[0].Class != reach.DNSFailure {
		t.Fatalf("unreached outcomes are not first: %+v", obs)
	}
	if _, still := back.Properties[Property]; still {
		t.Fatal("the property stayed on the report")
	}
	if Take(&back) != nil {
		t.Fatal("a second Take found observations")
	}
}

// What a report carries is bounded, so the runtime never refuses the
// report's info (and its other properties) for it.
func TestAttach_Bounded(t *testing.T) {
	var obs []Obs
	for i := range 5000 {
		obs = append(obs, Obs{Target: fmt.Sprintf("host-%d.example", i), Class: reach.Timeout, Detail: "i/o timeout"})
	}
	r := ctis.NewReport()
	Attach(r, obs)
	b, err := json.Marshal(r.Properties[Property])
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxAttachBytes {
		t.Fatalf("attached %d bytes, bound %d", len(b), maxAttachBytes)
	}
}

// SECURITY: only outcomes toward the job's own targets are recorded, under
// the job's target; an address outside an address or range target, and a
// local or link-local address for a name, are never reported.
func TestRecord_OnlyTheJobsTargets(t *testing.T) {
	targets := []string{"https://app.example.com", "10.1.2.0/24", "192.0.2.7"}
	rep, n := recorded(t, targets, []Obs{
		{Target: "app.example.com:443", Addr: "203.0.113.9", Port: 443, Class: reach.Reached},
		{Target: "evil.example.net", Addr: "198.51.100.1", Class: reach.NoRoute},     // not a job target
		{Target: "10.1.2.0/24", Addr: "10.1.2.9", Port: 22, Class: reach.NoRoute},    // inside the range
		{Target: "10.1.2.0/24", Addr: "10.1.3.9", Port: 22, Class: reach.Timeout},    // outside: no address
		{Target: "192.0.2.7", Addr: "192.0.2.8", Port: 80, Class: reach.PortClosed},  // another address: none
		{Target: "APP.example.com.", Addr: "169.254.169.254", Class: reach.Timeout},  // link-local: none
		{Target: "app.example.com", Addr: "127.0.0.1", Class: reach.FirewallRefused}, // loopback: none
	})
	if n != 6 {
		t.Fatalf("recorded %d, want 6 (the non-job target dropped)", n)
	}
	for _, u := range rep.UnreachedList {
		if u.Target == "evil.example.net" {
			t.Fatal("SECURITY: a target outside the job was recorded")
		}
	}
	if rep.Targets != 3 {
		t.Fatalf("targets = %d, want 3: %+v", rep.Targets, rep.Summary)
	}
	for _, b := range rep.Blocks {
		switch b.Block {
		case "203.0.113.0/24", "10.1.2.0/24", "192.0.2.0/24": // 192.0.2.0/24: the address target itself
		default:
			t.Errorf("SECURITY: block %s reported (an address outside its target, or local)", b.Block)
		}
	}
}

func TestRecord_NoRecorderIsANoOp(t *testing.T) {
	if n := Record(context.Background(), []string{"a"}, []Obs{{Target: "a", Class: reach.NoRoute}}); n != 0 {
		t.Fatalf("recorded %d without a recorder", n)
	}
}

func TestHostKey(t *testing.T) {
	cases := map[string]string{
		"https://App.Example.com:8443/x": "app.example.com",
		"app.example.com.":               "app.example.com",
		"app.example.com:443":            "app.example.com",
		"[2001:db8::1]:443":              "2001:db8::1",
		"2001:db8::1":                    "2001:db8::1",
		"10.0.0.0/8":                     "10.0.0.0/8",
		"::ffff:10.0.0.1":                "10.0.0.1",
	}
	for in, want := range cases {
		if got := hostKey(in); got != want {
			t.Errorf("hostKey(%q) = %q, want %q", in, got, want)
		}
	}
}
