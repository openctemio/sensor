package nuclei

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openctemio/sensor/internal/scanners/importparse"
)

// Every credential below is made up and matches no real token format, so
// secret scanners do not flag this file.
const (
	fakeBearer   = "fakebearer0000notarealtoken1111"
	fakeCookie   = "fakesession2222notreal3333"
	fakeAPIKey   = "fakeapikey4444notreal5555"
	fakePassword = "fakepass6666"
	fakeExposed  = "FAKEEXPOSED7777notarealsecret8888"
	fakeUserPass = "fakeuser:fakepw9999"
)

func sampleResult() Result {
	return Result{
		TemplateID: "fake-env-exposure",
		Info: TemplateInfo{
			Name:     "Fake .env exposure",
			Severity: "high",
			Tags:     []string{"exposure", "config"},
		},
		Host:    "app.example.test",
		Matched: "https://" + fakeUserPass + "@app.example.test/.env?api_key=" + fakeAPIKey + "&page=2",
		Request: "GET /.env?api_key=" + fakeAPIKey + "&page=2 HTTP/1.1\r\n" +
			"Host: app.example.test\r\n" +
			"Authorization: Bearer " + fakeBearer + "\r\n" +
			"Cookie: session=" + fakeCookie + "\r\n" +
			"User-Agent: nuclei\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/plain\r\n" +
			"Set-Cookie: session=" + fakeCookie + "; Path=/\r\n\r\n" +
			"DB_PASSWORD=" + fakePassword + "\nAPP_SECRET=" + fakeExposed + "\n",
		CurlCommand: "curl -X 'GET' -H 'Authorization: Bearer " + fakeBearer + "' -H 'Cookie: session=" + fakeCookie +
			"' 'https://app.example.test/.env?api_key=" + fakeAPIKey + "'",
		ExtractedResults: []string{fakeExposed},
	}
}

var allFakeSecrets = []string{fakeBearer, fakeCookie, fakeAPIKey, fakePassword, fakeExposed, "fakepw9999"}

func assertNoSecret(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range allFakeSecrets {
		if strings.Contains(text, s) {
			t.Errorf("%s leaks %q:\n%s", where, s, text)
		}
	}
}

// The report the sensor builds from a nuclei result carries none of the
// credentials in it: request, response and extracted values are left out or
// masked by the importer.
func TestNucleiReport_NoCredentials(t *testing.T) {
	line, err := json.Marshal(sampleResult())
	if err != nil {
		t.Fatal(err)
	}
	r, err := importparse.Nuclei().Parse(context.Background(), append(line, '\n'), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d", len(r.Findings))
	}
	b, _ := json.Marshal(r)
	assertNoSecret(t, "report JSON", string(b))
}

// A non-exposure template keeps the response body, with credentials in it
// redacted.
func TestRedactResponse_KeepsBodyOfOtherTemplates(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
		`{"user":"alice","access_token":"` + fakeBearer + `","role":"admin"}`
	got := redactResponse(resp, []string{"cve", "rce"}, nil)
	assertNoSecret(t, "response", got)
	if !strings.Contains(got, `"user":"alice"`) || !strings.Contains(got, `"role":"admin"`) {
		t.Errorf("non-secret body content lost:\n%s", got)
	}
	if !strings.Contains(got, `"access_token":"[REDACTED]"`) {
		t.Errorf("token not redacted in place:\n%s", got)
	}
}

func TestRedactText_Patterns(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"auth header keeps scheme", "Authorization: Basic " + fakeBearer, "Authorization: Basic [REDACTED]"},
		{"custom token header", "X-Auth-Token: " + fakeAPIKey, "X-Auth-Token: [REDACTED]"},
		{"plain header kept", "Content-Type: text/html", "Content-Type: text/html"},
		{"query param", "/a?token=" + fakeAPIKey + "&q=1", "/a?token=[REDACTED]&q=1"},
		{"exact short name", "/cb?code=" + fakeAPIKey + "&state_x=1", "/cb?code=[REDACTED]&state_x=1"},
		{"substring short name kept", "design=blue", "design=blue"},
		{"form body", "username=bob&password=" + fakePassword, "username=bob&password=[REDACTED]"},
		{"userinfo", "see https://" + fakeUserPass + "@host.test/x", "see https://[REDACTED]@host.test/x"},
		{"json", `{"client_secret": "` + fakeAPIKey + `"}`, `{"client_secret": "[REDACTED]"}`},
		{"yaml line", "password: " + fakePassword, "password: [REDACTED]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactText(tc.in, nil); got != tc.want {
				t.Errorf("redactText(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// An extracted value is hidden wherever it appears, under any name.
func TestRedactText_ExtractedValueEverywhere(t *testing.T) {
	in := "body: innocuous_field=" + fakeExposed + " and again " + fakeExposed
	got := redactText(in, []string{fakeExposed, "ok"})
	if strings.Contains(got, fakeExposed) {
		t.Fatalf("extracted value survived: %q", got)
	}
	if !strings.Contains(got, "and again") {
		t.Errorf("surrounding text lost: %q", got)
	}
}

func TestRedactURL(t *testing.T) {
	got := redactURL("https://" + fakeUserPass + "@h.test/p?access_token=" + fakeBearer + "&page=3#frag")
	assertNoSecret(t, "url", got)
	if !strings.Contains(got, "h.test/p") || !strings.Contains(got, "page=3") {
		t.Errorf("url lost its non-secret parts: %q", got)
	}
	if redactURL("https://h.test/p?page=1") != "https://h.test/p?page=1" {
		t.Error("a URL without credentials must be unchanged")
	}
}

// Redaction runs before the size cap, so a secret near the cut is never
// left half-visible, and the cut never splits a UTF-8 character.
func TestCapText_AfterRedaction(t *testing.T) {
	long := strings.Repeat("é", 3000) + " token=" + fakeAPIKey
	got := capText(redactText(long, nil), 4097)
	if !utf8.ValidString(got) {
		t.Fatal("cap split a UTF-8 character")
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Error("cut not marked")
	}
	half := fakeAPIKey[:len(fakeAPIKey)/2]
	if strings.Contains(capText(redactText("x token="+fakeAPIKey, nil), 12), half) {
		t.Error("a cut exposed part of a secret")
	}
}

func TestMaskExtracted_Caps(t *testing.T) {
	in := make([]string, 50)
	for i := range in {
		in[i] = fakeExposed
	}
	out := maskExtracted(in)
	if len(out) != maxExtractedResults {
		t.Fatalf("got %d values, want %d", len(out), maxExtractedResults)
	}
	for _, v := range out {
		if strings.Contains(v, fakeExposed) {
			t.Fatal("extracted value not masked")
		}
	}
}

// Validation evidence (re-verify) follows the same rules.
func TestSanitizeValidationEvidence_Redacted(t *testing.T) {
	ev := sanitizeValidationEvidence(sampleResult())
	b, _ := json.Marshal(ev)
	assertNoSecret(t, "validation evidence", string(b))
}
