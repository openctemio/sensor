package importparse

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", name)) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func repo() *core.ParseOptions {
	return &core.ParseOptions{AssetType: ctis.AssetTypeRepository, AssetValue: "github.com/example/shop"}
}

func TestMain(m *testing.M) {
	// Code parsers fall back to the CI job's repository; keep tests
	// independent of the runner.
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	os.Exit(m.Run())
}

func TestEveryScannerFormat(t *testing.T) {
	cases := []struct {
		p     *Parser
		input string
		opts  *core.ParseOptions
	}{
		{Semgrep(), "semgrep.json", repo()},
		{Betterleaks(), "betterleaks.json", repo()},
		{Trivy(), "trivy.json", nil},
		{Trivy(), "trivy-fs.json", repo()},
		{Nuclei(), "nuclei.jsonl", nil},
	}
	for _, tc := range cases {
		t.Run(tc.p.Name()+"/"+tc.input, func(t *testing.T) {
			data := fixture(t, tc.input)
			if !tc.p.CanParse(data) {
				t.Fatal("CanParse = false for its own format")
			}
			r, err := tc.p.Parse(context.Background(), data, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Findings) == 0 || r.Tool == nil || r.Tool.Name != tc.p.Name() {
				t.Fatalf("findings %d tool %+v", len(r.Findings), r.Tool)
			}
			if err := ctis.CheckFindingAssets(r); err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			if got := tc.p.SupportedFormats(); len(got) != 1 {
				t.Fatalf("formats %v", got)
			}
		})
	}
	if Semgrep().CanParse(fixture(t, "nuclei.jsonl")) || Nuclei().CanParse([]byte("not json")) {
		t.Fatal("CanParse accepted another format")
	}
}

// SECURITY: a code report the sensor cannot file on a repository is
// refused, never filed on a made-up asset.
func TestCodeReportWithoutRepositoryIsRefused(t *testing.T) {
	for _, p := range []*Parser{Semgrep(), Betterleaks()} {
		name := map[string]string{"semgrep": "semgrep.json", "betterleaks": "betterleaks.json"}[p.Name()]
		_, err := p.Parse(context.Background(), fixture(t, name), nil)
		if !errors.Is(err, ctis.ErrNoAssetForFindings) {
			t.Fatalf("%s: err = %v", p.Name(), err)
		}
	}
	// No finding: nothing to file, no error.
	if _, err := Betterleaks().Parse(context.Background(), []byte("[]"), nil); err != nil {
		t.Fatal(err)
	}
}

func TestBranchAndBasePath(t *testing.T) {
	raw := `[{"RuleID":"generic-api-key","Description":"key","StartLine":3,"EndLine":3,"Secret":"` + strings.Repeat("z", 20) +
		`","Match":"k","File":"/scan/src/app.py","Fingerprint":"/scan/src/app.py:generic-api-key:3"}]`
	opts := repo()
	opts.BasePath = "/scan"
	opts.BranchInfo = &ctis.BranchInfo{Name: "main", CommitSHA: "abc", IsDefaultBranch: true}
	r, err := Betterleaks().Parse(context.Background(), []byte(raw), opts)
	if err != nil {
		t.Fatal(err)
	}
	f := r.Findings[0]
	if f.Location.Path != "src/app.py" || f.Fingerprint != "src/app.py:generic-api-key:3" {
		t.Fatalf("scan root kept: %q %q", f.Location.Path, f.Fingerprint)
	}
	if r.Metadata.Branch == nil || r.Metadata.Branch.Name != "main" || !r.Metadata.Branch.IsDefaultBranch {
		t.Fatalf("branch %+v", r.Metadata.Branch)
	}
	legacy := repo()
	legacy.Branch, legacy.CommitSHA = "dev", "def"
	r, _ = Betterleaks().Parse(context.Background(), []byte(raw), legacy)
	if r.Metadata.Branch == nil || r.Metadata.Branch.Name != "dev" || r.Metadata.Branch.CommitSHA != "def" {
		t.Fatalf("legacy branch %+v", r.Metadata.Branch)
	}
}

// SECURITY: credentials in a matched URL never reach the report.
func TestNucleiURLCredentialsMasked(t *testing.T) {
	key := "fakekey" + "0123456789abcdef"
	line := `{"template-id":"env-exposure","info":{"name":"Exposed .env","severity":"high","tags":["exposure"]},"type":"http",` +
		`"host":"https://admin:` + key + `@app.example.test","matched-at":"https://app.example.test/.env?api_key=` + key + `&page=2"}` + "\n"
	r, err := Nuclei().Parse(context.Background(), []byte(line), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), key) {
		t.Fatalf("credential in the report: %s", b)
	}
	// CTIS 1.6 web URLs keep parameter names and drop every value
	// (weburl.RedactURL): the name says where the finding is.
	if !strings.Contains(string(b), "page=") {
		t.Fatalf("a query parameter name was lost: %s", b)
	}
}

// The template provenance the sensor annotates results with reaches the
// finding (the platform's re-check baseline), and only in a valid shape.
func TestNucleiTemplateProvenance(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	lines := `{"template-id":"a","template":"http/exposures/git-config.yaml","template-digest":"` + digest + `","info":{"name":"A","severity":"low"},"host":"203.0.113.1"}` + "\n\n" +
		`{"template-id":"b","template":"../../etc/passwd","template-digest":"md5:nope","info":{"name":"B","severity":"low"},"host":"203.0.113.2"}` + "\n"
	r, err := Nuclei().Parse(context.Background(), []byte(lines), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings %d", len(r.Findings))
	}
	a, b := r.Findings[0], r.Findings[1]
	if a.Properties["template_digest"] != digest || a.Properties["template_path"] != "http/exposures/git-config.yaml" {
		t.Fatalf("provenance %v", a.Properties)
	}
	if _, ok := b.Properties["template_digest"]; ok {
		t.Fatal("a malformed digest was kept")
	}
	if _, ok := b.Properties["template_path"]; ok {
		t.Fatal("a non-local template path was kept")
	}
}

func TestNucleiUnusableOutputIsAnError(t *testing.T) {
	if _, err := Nuclei().Parse(context.Background(), []byte("garbage\n{\"x\":1}\n"), nil); err == nil {
		t.Fatal("output with no usable result was accepted")
	}
}

// The out-of-process path's output is a checked, stamped CTIS report: read
// as it is, findings without an asset filed on the scan target.
func TestToolReportPassthrough(t *testing.T) {
	rep := ctis.Report{Version: "1.5", Tool: &ctis.Tool{Name: "nuclei"},
		Metadata: ctis.ReportMetadata{Properties: ctis.Properties{"provenance": map[string]any{"tool": "nuclei"}}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityLow}}}
	data, _ := json.Marshal(rep)
	if !IsToolReport(data, "nuclei") || IsToolReport(data, "trivy") || IsToolReport([]byte("[]"), "nuclei") {
		t.Fatal("IsToolReport")
	}
	if _, err := Nuclei().Parse(context.Background(), data, nil); !errors.Is(err, ctis.ErrNoAssetForFindings) {
		t.Fatalf("no target: %v", err)
	}
	r, err := Nuclei().Parse(context.Background(), data, &core.ParseOptions{AssetValue: "https://shop.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 1 || r.Findings[0].AssetRef != r.Assets[0].ID {
		t.Fatalf("assets %+v", r.Assets)
	}
}
