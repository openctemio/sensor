package betterleaks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/scanners/importparse"
)

// No plaintext secret may leave the parser: the whole CTIS report (which is
// what gets pushed to the platform) is serialized and searched for it.
func TestParser_NeverEmitsPlaintextSecret(t *testing.T) {
	secrets := []struct {
		name, secret, match string
	}{
		{"aws key in assignment", "AKIAIOSFODNN7EXAMPLE", `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`},
		{"github token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", `token: ghp_abcdefghijklmnopqrstuvwxyz0123456789 # ci`},
		{"short secret", "hunter2x", `password=hunter2x`},
		{"secret not verbatim in match", "s3cr3t-value-123456", `PASSWORD="s3cr3t-value-12345 (truncated by scanner)`},
		{"multi-line private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAw\n-----END RSA PRIVATE KEY-----",
			"key = \"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAw\n-----END RSA PRIVATE KEY-----\""},
	}
	for _, tc := range secrets {
		t.Run(tc.name, func(t *testing.T) {
			findings := []Finding{{
				RuleID: "generic-api-key", Description: "Generic API Key",
				File: "config/app.env", StartLine: 3, EndLine: 3,
				Match: tc.match, Secret: tc.secret, Fingerprint: "config/app.env:generic-api-key:3",
			}}
			raw, _ := json.Marshal(findings)

			report, err := importparse.Betterleaks().Parse(context.Background(), raw, &core.ParseOptions{AssetValue: "github.com/example/app"})
			if err != nil {
				t.Fatal(err)
			}
			out, _ := json.Marshal(report)
			if strings.Contains(string(out), tc.secret) {
				t.Fatalf("plaintext secret in CTIS report: %s", out)
			}
			// JSON escapes newlines; check the escaped form too.
			esc, _ := json.Marshal(tc.secret)
			if strings.Contains(string(out), strings.Trim(string(esc), `"`)) {
				t.Fatalf("plaintext (escaped) secret in CTIS report: %s", out)
			}
			if len(report.Findings) != 1 || report.Findings[0].Location == nil || report.Findings[0].Location.Snippet == "" {
				t.Fatalf("snippet should still carry masked context")
			}

			// The SecretResult path (Scanner.convertFindings) must not leak either.
			res := (&Scanner{}).convertFindings(findings)
			b, _ := json.Marshal(res)
			if strings.Contains(string(b), strings.Trim(string(esc), `"`)) {
				t.Fatalf("plaintext secret in SecretResult: %s", b)
			}
		})
	}
}
