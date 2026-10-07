package betterleaks

import (
	"encoding/json"
	"strings"
	"testing"
)

// The rule description (the title) and the commit message can repeat the
// raw secret; it must reach no field of the finding. The fake token is
// assembled at run time so that no secret scanner flags this repository.
func TestConvertFinding_SecretMaskedEverywhere(t *testing.T) {
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
	got := (&Parser{}).convertFinding(f, 0, nil)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), token) {
		t.Fatalf("raw secret in the finding: %s", b)
	}
	if !strings.Contains(got.Title, "ghp_") {
		t.Errorf("title %q lost the masked prefix", got.Title)
	}
}
