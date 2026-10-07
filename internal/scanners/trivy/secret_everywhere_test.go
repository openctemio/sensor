package trivy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sensor/internal/scanners/importparse"
)

// A trivy run with masking turned off leaves the secret in the match, the
// code lines and the title; it must reach no field of the report.
func TestTrivySecretMaskedEverywhere(t *testing.T) {
	key := "AKIA" + "Q3EGRZ7X2MNVBP4L"
	out := map[string]any{
		"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem",
		"Results": []any{map[string]any{
			"Target": "config.py", "Class": "secret",
			"Secrets": []any{map[string]any{
				"RuleID": "aws-access-key-id", "Category": "AWS", "Severity": "CRITICAL",
				"Title": "AWS Access Key " + key, "StartLine": 2, "EndLine": 2,
				"Match": "key = " + key,
				"Code":  map[string]any{"Lines": []any{map[string]any{"Number": 2, "Content": "key = " + key, "IsCause": true}}},
			}},
		}},
	}
	data, _ := json.Marshal(out)
	r, err := importparse.Trivy().Parse(context.Background(), data,
		&core.ParseOptions{AssetType: ctis.AssetTypeRepository, AssetValue: "github.com/example/app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d", len(r.Findings))
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), key) {
		t.Fatalf("raw secret in the report: %s", b)
	}
}
