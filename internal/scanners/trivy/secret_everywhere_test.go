package trivy

import (
	"encoding/json"
	"strings"
	"testing"
)

// A trivy run with masking turned off leaves the secret in the match, the
// code lines and the title; it must reach no field of the finding.
func TestParseSecret_SecretMaskedEverywhere(t *testing.T) {
	key := "AKIA" + "Q3EGRZ7X2MNVBP4L"
	s := &Secret{
		RuleID: "aws-access-key-id", Category: "AWS", Severity: "CRITICAL",
		Title: "AWS Access Key " + key, StartLine: 2, EndLine: 2,
		Match: "key = " + key,
		Code:  Code{Lines: []CodeLine{{Number: 2, Content: "key = " + key, IsCause: true}}},
	}
	got := NewParser().parseSecret(&Result{Target: "config.py"}, s, nil)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), key) {
		t.Fatalf("raw secret in the finding: %s", b)
	}
}
