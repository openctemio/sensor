package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sensor/internal/gate"
)

const fakeRunToken = "octci_SENSORTESTTOKEN0123456789abcdefghijklmnopq"

func fakePlatform(t *testing.T, verdict string, evalStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/gh", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gh-oidc-token"})
	})
	mux.HandleFunc("/api/v1/ci/oidc/exchange", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "r1", "token": fakeRunToken, "expires_at": time.Now().Add(15 * time.Minute)})
	})
	mux.HandleFunc("/api/v1/ci/runs/r1/evaluate", func(w http.ResponseWriter, _ *http.Request) {
		if evalStatus != http.StatusOK {
			w.WriteHeader(evalStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"verdict": verdict,
			"reasons": []map[string]any{{"code": "secret", "message": "a secret is committed", "file": "config.go", "line": 3}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func ghEnv(srv *httptest.Server, tenant string) func(string) string {
	env := map[string]string{"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "/gh?v=1",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req", "OPENCTEM_TENANT_ID": tenant}
	return func(k string) string { return env[k] }
}

func TestOpenCIRun(t *testing.T) {
	srv := fakePlatform(t, "pass", http.StatusOK)
	var stderr bytes.Buffer
	if run := openCIRun(srv.URL, &stderr, ghEnv(srv, "t1")); run == nil || run.Provider() != "github" {
		t.Fatalf("github job: %v %s", run, stderr.String())
	}
	// Not configured: silent, falls back to the API key.
	stderr.Reset()
	if run := openCIRun(srv.URL, &stderr, func(string) string { return "" }); run != nil || stderr.Len() != 0 {
		t.Fatalf("no tenant: %v %q", run, stderr.String())
	}
	// Tenant set, no token: says how to grant it.
	stderr.Reset()
	if run := openCIRun(srv.URL, &stderr, func(k string) string {
		return map[string]string{"OPENCTEM_TENANT_ID": "t1", "GITHUB_ACTIONS": "true"}[k]
	}); run != nil || !strings.Contains(stderr.String(), "id-token: write") {
		t.Fatalf("no token: %v %q", run, stderr.String())
	}
}

func TestCIGateExit(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		verdict     string
		status      int
		failOn      string
		wantCode    int
		wantDecided bool
	}{
		{"pass", "pass", http.StatusOK, "", gate.ExitCodePass, true},
		{"fail", "fail", http.StatusOK, "", gate.ExitCodeFail, true},
		{"fail ignores the local threshold", "fail", http.StatusOK, "critical", gate.ExitCodeFail, true},
		{"unreachable without fallback", "", http.StatusBadGateway, "", gate.ExitCodeError, true},
		{"unreachable falls back to -fail-on", "", http.StatusBadGateway, "high", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakePlatform(t, tc.verdict, tc.status)
			var stderr bytes.Buffer
			run := openCIRun(srv.URL, &stderr, ghEnv(srv, "t1"))
			var stdout bytes.Buffer
			code, decided := ciGateExit(ctx, run, 0, tc.failOn, &stdout, &stderr)
			if code != tc.wantCode || decided != tc.wantDecided {
				t.Fatalf("code %d decided %v; out %s err %s", code, decided, stdout.String(), stderr.String())
			}
			out := stdout.String() + stderr.String()
			if strings.Contains(out, fakeRunToken) || strings.Contains(out, "gh-oidc-token") {
				t.Fatalf("a token was printed: %s", out)
			}
			if tc.verdict == "fail" && !strings.Contains(stdout.String(), "config.go:3") {
				t.Fatalf("reasons not printed: %s", stdout.String())
			}
		})
	}
}

func TestInCI(t *testing.T) {
	if !inCI(func(k string) string { return map[string]string{"GITLAB_CI": "true"}[k] }) || inCI(func(string) string { return "" }) {
		t.Fatal("CI detection")
	}
}
