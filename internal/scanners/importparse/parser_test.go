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
	if f.Location.Path != "src/app.py" || f.PartialFingerprints["leaksFingerprint/v1"] != "src/app.py:generic-api-key:3" {
		t.Fatalf("scan root kept: %q %v", f.Location.Path, f.PartialFingerprints)
	}
	// A secret fingerprint over the checkout path cannot be computed again
	// over the relative one (the raw secret is gone): it is left to the
	// platform rather than sent tied to where the repository was checked
	// out.
	if f.Fingerprint != "" {
		t.Fatalf("fingerprint over the scan root kept: %q", f.Fingerprint)
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
// rule catalog (the platform's re-check baseline), and only in a valid shape:
// one rule per template, its revision (content_sha256) and its place in the
// content pack (content_path); every finding names its rule.
func TestNucleiTemplateProvenance(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	lines := `{"template-id":"a","template":"http/exposures/git-config.yaml","template-digest":"sha256:` + digest + `","info":{"name":"A","severity":"low"},"host":"203.0.113.1"}` + "\n\n" +
		`{"template-id":"b","template":"../../etc/passwd","template-digest":"md5:nope","info":{"name":"B","severity":"low"},"host":"203.0.113.2"}` + "\n" +
		`{"template-id":"a","template":"http/exposures/git-config.yaml","template-digest":"sha256:` + digest + `","info":{"name":"A","severity":"low"},"host":"203.0.113.3"}` + "\n"
	r, err := Nuclei().Parse(context.Background(), []byte(lines), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 || len(r.Rules) != 2 {
		t.Fatalf("findings %d, rules %d (want one rule per template)", len(r.Findings), len(r.Rules))
	}
	rules := map[string]ctis.Rule{}
	for _, rule := range r.Rules {
		rules[rule.ID] = rule
		if ctis.IsUUIDShaped(rule.ID) || !ctis.IsDocumentRef(rule.ID) {
			t.Fatalf("rule id %q is not a document-local reference", rule.ID)
		}
	}
	for _, f := range r.Findings {
		rule, ok := rules[f.RuleRef]
		if !ok || rule.RuleID != f.RuleID {
			t.Fatalf("finding %q names rule %q (%+v)", f.RuleID, f.RuleRef, rule)
		}
		for _, k := range []string{"template_digest", "template_path"} {
			if _, ok := f.Properties[k]; ok {
				t.Fatalf("finding still carries the %s property", k)
			}
		}
	}
	a, b := rules[r.Findings[0].RuleRef], rules[r.Findings[1].RuleRef]
	if a.ContentSHA256 != digest || a.ContentPath != "http/exposures/git-config.yaml" {
		t.Fatalf("provenance %+v", a)
	}
	if b.ContentSHA256 != "" {
		t.Fatal("a malformed digest was kept")
	}
	if b.ContentPath != "" {
		t.Fatal("a non-local template path was kept")
	}
	r.Metadata.ID = ctis.NewReportID()
	if err := r.Validate(); err != nil {
		t.Fatalf("the report is not valid CTIS: %v", err)
	}
}

// A result of one of the organization's own templates keeps its
// tenant:-prefixed rule id and its rule is marked rule_source tenant
// (extensions["io.openctem"]); a platform result's rule carries no rule
// source, whatever a template id says.
func TestNucleiTenantRuleSource(t *testing.T) {
	lines := `{"template-id":"tenant:login-panel","rule-source":"tenant","template":"login.yaml","info":{"name":"A","severity":"low"},"host":"203.0.113.1"}` + "\n" +
		`{"template-id":"login-panel","rule-source":"platform","info":{"name":"B","severity":"low"},"host":"203.0.113.2"}` + "\n"
	r, err := Nuclei().Parse(context.Background(), []byte(lines), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || len(r.Rules) != 2 {
		t.Fatalf("findings %d, rules %d", len(r.Findings), len(r.Rules))
	}
	a, b := r.Rules[0], r.Rules[1]
	if src, _ := a.Extensions.Get(ctis.OpenCTEMNamespace, "rule_source"); a.RuleID != "tenant:login-panel" || src != "tenant" {
		t.Fatalf("organization rule: %+v", a)
	}
	if _, ok := b.Extensions.Get(ctis.OpenCTEMNamespace, "rule_source"); b.RuleID != "login-panel" || ok {
		t.Fatalf("platform rule: %+v", b)
	}
	for _, f := range r.Findings {
		if f.Properties["rule_source"] != nil {
			t.Fatalf("finding still carries rule_source: %v", f.Properties)
		}
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
	rep := ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"},
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

// The template file nuclei prints is a path on this sensor's disk; the
// report carries its place in the content pack instead.
func TestNucleiTemplatePathIsNotSensorLocal(t *testing.T) {
	abs := "/var/lib/openctem/content/nuclei-templates/versions/20261005T083220.302831790Z-7ae245/http/vulnerabilities/wordpress/wordpress-click2shell.yaml"
	lines := `{"template-id":"a","template-path":"` + abs + `","template":"http/vulnerabilities/wordpress/wordpress-click2shell.yaml","info":{"name":"A","severity":"low"},"host":"203.0.113.1"}` + "\n" +
		`{"template-id":"b","template-path":"/opt/private/x.yaml","info":{"name":"B","severity":"low"},"host":"203.0.113.2"}` + "\n" +
		`{"template-id":"c","template-path":"/opt/private/y.yaml","template":"http/y.yaml","info":{"name":"C","severity":"low"},"host":"203.0.113.3"}` + "\n"
	r, err := Nuclei().Parse(context.Background(), []byte(lines), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("findings %d", len(r.Findings))
	}
	path := func(i int) string {
		for _, rule := range r.Rules {
			if rule.ID == r.Findings[i].RuleRef {
				return rule.ContentPath
			}
		}
		t.Fatalf("finding %d names no rule", i)
		return ""
	}
	if got := path(0); got != "nuclei-templates/versions/20261005T083220.302831790Z-7ae245/http/vulnerabilities/wordpress/wordpress-click2shell.yaml" {
		t.Fatalf("release path = %q", got)
	}
	if v := path(1); v != "" {
		t.Fatalf("an unknown sensor path was kept: %q", v)
	}
	if got := path(2); got != "http/y.yaml" {
		t.Fatalf("relative fallback = %q", got)
	}
	for _, f := range r.Findings {
		if _, ok := f.SourceExtra["template_path"]; ok {
			t.Fatalf("source_extra still carries template_path: %v", f.SourceExtra)
		}
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "/var/lib/openctem") || strings.Contains(string(b), "/opt/private") {
		t.Fatalf("sensor path in the report: %s", b)
	}
}

// SECURITY: a secret enters a fingerprint only as HMAC-SHA256 with the
// sensor's key (CTIS recipe ctis-fp/2); without the key there is none, never
// an unsalted hash of the secret.
func TestSecretFingerprintNeedsTheSensorKey(t *testing.T) {
	secret := strings.Repeat("q", 24)
	raw := `[{"RuleID":"generic-api-key","Description":"key","StartLine":3,"EndLine":3,"Secret":"` + secret +
		`","Match":"k","File":"src/app.py"}]`
	opts := repo()
	r, err := Betterleaks().Parse(context.Background(), []byte(raw), opts)
	if err != nil {
		t.Fatal(err)
	}
	if fp := r.Findings[0].Fingerprint; fp != "" {
		t.Fatalf("fingerprint without a key: %q", fp)
	}
	opts.SecretKey = []byte(strings.Repeat("k", 32))
	r, err = Betterleaks().Parse(context.Background(), []byte(raw), opts)
	if err != nil {
		t.Fatal(err)
	}
	fp := r.Findings[0].Fingerprint
	if !strings.HasPrefix(fp, "ctis-fp/2:") || strings.Contains(fp, secret) {
		t.Fatalf("keyed fingerprint %q", fp)
	}
	other := repo()
	other.SecretKey = []byte(strings.Repeat("o", 32))
	r2, _ := Betterleaks().Parse(context.Background(), []byte(raw), other)
	if r2.Findings[0].Fingerprint == fp {
		t.Fatal("the fingerprint does not depend on the sensor key")
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), secret) || strings.Contains(string(b), string(opts.SecretKey)) {
		t.Fatalf("secret or key in the report: %s", b)
	}
}
