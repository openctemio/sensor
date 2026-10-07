package executor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// A scan job admitted by the sensor-local policy: "*.x" covers x itself and
// every name below it, in allow and in deny (api RFC-054 §4.1, the platform's
// reading of the same pattern).
func TestLocalPolicy_WildcardCoversApex(t *testing.T) {
	lp := policyForTest(t, `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["*.corp.example.com"]
  deny: ["*.prod.corp.example.com"]
`, map[string][]string{
		"corp.example.com":         {"203.0.113.10"},
		"www.corp.example.com":     {"203.0.113.11"},
		"prod.corp.example.com":    {"203.0.113.12"},
		"db.prod.corp.example.com": {"203.0.113.13"},
		"notcorp.example.com":      {"203.0.113.14"},
	})
	payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{
		"corp.example.com", "https://www.corp.example.com/", "prod.corp.example.com",
		"db.prod.corp.example.com", "notcorp.example.com",
	}})
	cmd := &core.Command{ID: "s1", Type: "scan", Payload: payload}
	adm, err := lp.AdmitCommandTargets(context.Background(), cmd)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	got := map[string]string{}
	for _, r := range adm.Refused {
		got[r.Target] = r.Rule
	}
	want := map[string]string{
		"prod.corp.example.com":    "targets.deny",
		"db.prod.corp.example.com": "targets.deny",
		"notcorp.example.com":      "targets.allow",
	}
	if len(got) != len(want) {
		t.Fatalf("refused %v, want %v", got, want)
	}
	for target, rule := range want {
		if got[target] != rule {
			t.Errorf("%s: rule %q, want %q", target, got[target], rule)
		}
	}
	var rewritten struct {
		Targets []string `json:"targets"`
	}
	_ = json.Unmarshal(cmd.Payload, &rewritten)
	if len(rewritten.Targets) != 2 || rewritten.Targets[0] != "corp.example.com" {
		t.Errorf("admitted targets %v, want the apex and www", rewritten.Targets)
	}
}
