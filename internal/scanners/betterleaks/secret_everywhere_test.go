package betterleaks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/importparse"
)

// The rule description (the title) and the commit message can repeat the
// raw secret; it must reach no field of the report. The fake token is
// assembled at run time so that no secret scanner flags this repository.
func TestBetterleaksSecretMaskedEverywhere(t *testing.T) {
	token := "ghp_" + "9fK2xLq7RzT4mWv8Np3Yb6Hc"
	f := Finding{
		Description: "GitHub token " + token,
		RuleID:      "github-pat",
		File:        "ci.yml",
		StartLine:   4,
		Match:       "token: " + token,
		Secret:      token,
		Message:     "add " + token,
	}
	raw, err := json.Marshal([]Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	r, err := importparse.Betterleaks().Parse(context.Background(), raw, &core.ParseOptions{AssetValue: "github.com/example/app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d", len(r.Findings))
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), token) {
		t.Fatalf("raw secret in the report: %s", b)
	}
	if mv := r.Findings[0].Secret; mv == nil || !strings.HasPrefix(mv.MaskedValue, "ghp_") {
		t.Errorf("masked value %+v lost the prefix", mv)
	}
}
