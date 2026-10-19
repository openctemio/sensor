package nuclei

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// fakeRuleSourcesNuclei records each run's arguments and whether it got a
// signer certificate, and prints one result per template directory it was
// given: a template of a "nuclei-signed" or custom directory as "mine",
// any other as "platform".
func fakeRuleSourcesNuclei(t *testing.T) (bin, record, certs string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "nuclei")
	record = filepath.Join(dir, "runs")
	certs = filepath.Join(dir, "certs")
	script := `#!/bin/sh
echo "$*" >> "` + record + `"
printf '%s' "$NUCLEI_USER_CERTIFICATE" > "` + certs + `"
prev=""
for a in "$@"; do
  if [ "$prev" = "-t" ]; then
    for f in "$a"/*.yaml; do
      [ -f "$f" ] || continue
      case "$f" in
        */platform/*) id=platform ;;
        *) id=mine ;;
      esac
      printf '{"template-id":"%s","template-path":"%s","info":{"name":"t","severity":"info"},"host":"h","matched-at":"h"}\n' "$id" "$f"
    done
  fi
  prev="$a"
done
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, record, certs
}

// platformSet is a sensor-managed template directory with one template.
func platformSet(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "platform")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cve.yaml"), []byte(httpTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func ruleSourcesScanner(t *testing.T) (*Scanner, string, string, string) {
	t.Helper()
	t.Setenv("OPENCTEM_EGRESS_PROXY", "")
	bin, record, certs := fakeRuleSourcesNuclei(t)
	s := NewScanner()
	s.Binary = bin
	s.TemplateDir = platformSet(t)
	return s, s.TemplateDir, record, certs
}

// nucleiVerify checks a signed template the way nuclei does: the last
// "# digest: " line, ECDSA over SHA-256 of the trimmed content, gob-encoded,
// and the signer fragment.
func nucleiVerify(t *testing.T, certPEM, signed []byte) bool {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.Subject.CommonName == "" {
		t.Fatalf("certificate: %v (common name %q)", err, cert.Subject.CommonName)
	}
	pub := cert.PublicKey.(*ecdsa.PublicKey)
	i := bytes.LastIndex(signed, []byte(signaturePrefix))
	if i < 0 {
		return false
	}
	sigLine := strings.TrimSpace(string(signed[i:]))
	content := bytes.ReplaceAll(bytes.TrimSpace(signed[:i]), []byte("\r\n"), []byte("\n"))
	fragment, err := publicKeyFragment(pub)
	if err != nil {
		t.Fatal(err)
	}
	digestHex := strings.TrimSuffix(strings.TrimPrefix(sigLine, signaturePrefix), ":"+fragment)
	if digestHex == strings.TrimPrefix(sigLine, signaturePrefix) {
		return false // no fragment of this signer
	}
	raw, err := hex.DecodeString(digestHex)
	if err != nil {
		return false
	}
	var sig []byte
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&sig); err != nil {
		return false
	}
	sum := sha256.Sum256(content)
	return ecdsa.VerifyASN1(pub, sum[:], sig)
}

// Rule sources "both": ONE nuclei run with the sensor's own set and the
// custom templates, signatures still enforced; the custom templates are
// signed copies nuclei verifies with the run's certificate, the received
// files are untouched, and the results of the custom templates are marked
// as the organization's.
func TestBothRunsOneInvocationWithSignedCustomTemplates(t *testing.T) {
	s, own, record, certs := ruleSourcesScanner(t)
	s.Headless = true
	custom := writeTemplates(t, map[string]string{"probe.yaml": httpTemplate})

	res, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{CustomTemplateDir: custom, RuleSources: core.RuleSourcesBoth})
	if err != nil {
		t.Fatal(err)
	}
	runs := readRuns(t, record)
	if len(runs) != 1 {
		t.Fatalf("runs = %q, want one invocation", runs)
	}
	args := strings.Fields(runs[0])
	var tdirs []string
	for i, a := range args {
		if a == "-t" && i+1 < len(args) {
			tdirs = append(tdirs, args[i+1])
		}
	}
	if len(tdirs) != 2 || tdirs[0] != own || !strings.Contains(tdirs[1], "nuclei-signed-") {
		t.Fatalf("-t %v: want the own set and the run's signed copies", tdirs)
	}
	if slices.Contains(args, custom) {
		t.Errorf("args %v: the unsigned received templates were handed to nuclei", args)
	}
	for _, want := range []string{"-disable-unsigned-templates", "-lna"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v: want %s", args, want)
		}
	}
	if slices.Contains(args, "-exclude-type") {
		t.Errorf("args %v: a type filter would drop the own set's templates too", args)
	}

	cert, err := os.ReadFile(certs)
	if err != nil || !bytes.Contains(cert, []byte("CERTIFICATE")) {
		t.Fatalf("nuclei got no signer certificate (%v): %q", err, cert)
	}
	// The signed copy is gone after the run; sign again to check the format
	// nuclei verifies, and that a tampered copy fails.
	signed, cleanup, err := signCustomTemplates(custom)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	body, err := os.ReadFile(filepath.Join(signed.dir, "probe.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !nucleiVerify(t, signed.certPEM, body) {
		t.Fatal("nuclei would not verify the signed copy")
	}
	if nucleiVerify(t, signed.certPEM, bytes.Replace(body, []byte("GET"), []byte("PUT"), 1)) {
		t.Fatal("a tampered copy verified")
	}
	if nucleiVerify(t, cert, body) {
		t.Fatal("another run's certificate verified this run's copy")
	}
	if got, _ := os.ReadFile(filepath.Join(custom, "probe.yaml")); string(got) != httpTemplate {
		t.Fatal("the received template was changed")
	}

	// Results: the custom template's id is namespaced, marked as the
	// organization's, and carries the digest of the template as received.
	sum := sha256.Sum256([]byte(httpTemplate))
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	var sawMine, sawPlatform bool
	for _, line := range strings.Split(strings.TrimSpace(string(res.RawOutput)), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		switch r["template-id"] {
		case "tenant:mine":
			sawMine = true
			if r["rule-source"] != "tenant" || r["template-digest"] != wantDigest {
				t.Errorf("custom result %v: want rule-source tenant and digest %s", r, wantDigest)
			}
		case "platform":
			sawPlatform = true
			if _, ok := r["rule-source"]; ok {
				t.Errorf("platform result marked as the organization's: %v", r)
			}
		default:
			t.Errorf("unexpected result %v", r)
		}
	}
	if !sawMine || !sawPlatform {
		t.Fatalf("output %q: want one platform and one organization result", res.RawOutput)
	}
}

// Without -disable-unsigned-templates there is nothing to sign: one run
// with the received custom templates.
func TestBothWithoutSignatureEnforcementUsesTheReceivedTemplates(t *testing.T) {
	s, own, record, certs := ruleSourcesScanner(t)
	s.DisableUnsignedTemplates = false
	custom := writeTemplates(t, map[string]string{"probe.yaml": httpTemplate})
	if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{CustomTemplateDir: custom}); err != nil {
		t.Fatal(err)
	}
	runs := readRuns(t, record)
	args := strings.Fields(runs[0])
	if len(runs) != 1 || !slices.Contains(args, own) || !slices.Contains(args, custom) {
		t.Fatalf("runs %q: want one run with both directories", runs)
	}
	if cert, _ := os.ReadFile(certs); len(cert) != 0 {
		t.Fatal("a certificate was handed out without signing")
	}
}

func TestPlatformOnlyAndContradictions(t *testing.T) {
	s, own, record, _ := ruleSourcesScanner(t)
	if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{RuleSources: core.RuleSourcesPlatform}); err != nil {
		t.Fatal(err)
	}
	runs := readRuns(t, record)
	if args := strings.Fields(runs[0]); len(runs) != 1 || !slices.Contains(args, own) || slices.Contains(args, "-lna") {
		t.Fatalf("platform-only runs %q: want the own set alone", runs)
	}
	custom := writeTemplates(t, map[string]string{"probe.yaml": httpTemplate})
	if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{CustomTemplateDir: custom, RuleSources: core.RuleSourcesPlatform}); err == nil {
		t.Fatal("platform-only with custom templates ran")
	}
	if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{RuleSources: core.RuleSourcesTenant}); err == nil {
		t.Fatal("tenant-only without templates ran (it would run the platform's rules)")
	}
	if got := readRuns(t, record); len(got) != 1 {
		t.Fatalf("refused scans started nuclei: %q", got)
	}
}

// A dangerous custom template stops a "both" scan before nuclei starts or
// anything is signed.
func TestBothRefusesDangerousCustomTemplates(t *testing.T) {
	s, _, record, _ := ruleSourcesScanner(t)
	for name, body := range map[string]string{
		"flow":       "id: x\ninfo: {name: x, severity: info}\nflow: http(1)\nhttp: []\n",
		"javascript": "id: x\ninfo: {name: x, severity: info}\njavascript:\n  - code: 'x'\n",
		"code":       "id: x\ninfo: {name: x, severity: info}\ncode:\n  - engine: [sh]\n    source: id\n",
	} {
		custom := writeTemplates(t, map[string]string{"bad.yaml": body})
		if _, err := s.Scan(context.Background(), "https://203.0.113.10", &core.ScanOptions{CustomTemplateDir: custom}); err == nil {
			t.Fatalf("%s: a dangerous custom template ran", name)
		}
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("nuclei was started")
	}
}

func TestSignableContentIgnoresAReceivedSignature(t *testing.T) {
	in := []byte("id: x\r\ninfo: {name: x}\r\n# digest: deadbeef:cafe\n")
	if got := string(signableContent(in)); got != "id: x\ninfo: {name: x}" {
		t.Fatalf("signableContent = %q", got)
	}
}

// The run signs the received template up to its last "# digest: " line; a
// template whose signed part differs from what was checked is refused.
func TestSignCustomTemplatesChecksTheSignedBytes(t *testing.T) {
	body := "id: x\ninfo: {name: x, author: [a], severity: info}\nhttp:\n  - path: ['{{BaseURL}}']\n    body: \"a\n# digest: b\"\n"
	custom := writeTemplates(t, map[string]string{"cut.yaml": body})
	if out, cleanup, err := signCustomTemplates(custom); err == nil {
		cleanup()
		t.Fatalf("signed a template cut at an inner signature line: %v", out.digests)
	}
}
