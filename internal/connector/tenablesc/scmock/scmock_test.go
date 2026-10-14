package scmock

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func call(t *testing.T, h http.Handler, key, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("x-apikey", key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return rec.Code, env
}

func TestMock_AuthLicenceAndRepositoryDelete(t *testing.T) {
	m := New(Options{
		AccessKey: "a", SecretKey: "s", LicensedIPs: 1,
		Repositories: []Named{{ID: 5, Name: "rotation"}}, Policies: []Named{{ID: 1, Name: "p"}},
		Hosts: []Host{
			{IP: "10.0.0.1", Alive: true, Vulns: []Vuln{{PluginID: "1000", Severity: 2}}},
			{IP: "10.0.0.2", Alive: true, Vulns: []Vuln{{PluginID: "19506"}}}, // discovery only: not licensed
			{IP: "10.0.0.3", Alive: true, Vulns: []Vuln{{PluginID: "1001", Severity: 3}}},
		},
		RunningReads: 1,
	})
	h := m.Handler()
	key := "accesskey=a; secretkey=s;"
	if code, _ := call(t, h, "accesskey=a; secretkey=x;", "GET", "/rest/status", nil); code != 401 {
		t.Fatalf("wrong key: %d", code)
	}
	scan := func(ipList string) string {
		_, env := call(t, h, key, "POST", "/rest/scan", map[string]any{"name": "n", "type": "policy", "ipList": ipList,
			"repository": map[string]string{"id": "5"}, "policy": map[string]string{"id": "1"}})
		id := env["response"].(map[string]any)["id"].(string)
		_, env = call(t, h, key, "POST", "/rest/scan/"+id+"/launch", map[string]any{})
		rid := env["response"].(map[string]any)["scanResult"].(map[string]any)["id"].(string)
		var st map[string]any
		for range 6 {
			_, env = call(t, h, key, "GET", "/rest/scanResult/"+rid, nil)
			st = env["response"].(map[string]any)
		}
		return st["importStatus"].(string)
	}
	if got := scan("10.0.0.1,10.0.0.2"); got != "Finished" || m.ActiveIPs() != 1 {
		t.Fatalf("first import %q active %d", got, m.ActiveIPs())
	}
	if got := scan("10.0.0.3"); got != "Blocked" || m.ActiveIPs() != 1 {
		t.Fatalf("over-licence import %q active %d", got, m.ActiveIPs())
	}
	if code, _ := call(t, h, key, "DELETE", "/rest/repository/5", nil); code != 200 || m.ActiveIPs() != 0 {
		t.Fatalf("repository delete %d active %d", code, m.ActiveIPs())
	}
}

func TestMock_PartialScans(t *testing.T) {
	m := New(Options{AccessKey: "a", SecretKey: "s", LicensedIPs: 10, PartialScans: true, RunningReads: 1,
		Repositories: []Named{{ID: 5, Name: "r"}}, Policies: []Named{{ID: 1, Name: "p"}},
		Hosts: []Host{{IP: "10.0.0.1", Alive: true}, {IP: "10.0.0.2", Alive: true}}})
	h := m.Handler()
	key := "accesskey=a; secretkey=s;"
	_, env := call(t, h, key, "POST", "/rest/scan", map[string]any{"name": "n", "type": "policy", "ipList": "10.0.0.0/30",
		"repository": map[string]string{"id": "5"}, "policy": map[string]string{"id": "1"}})
	id := env["response"].(map[string]any)["id"].(string)
	_, env = call(t, h, key, "POST", "/rest/scan/"+id+"/launch", map[string]any{})
	rid := env["response"].(map[string]any)["scanResult"].(map[string]any)["id"].(string)
	var st map[string]any
	for range 4 {
		_, env = call(t, h, key, "GET", "/rest/scanResult/"+rid, nil)
		st = env["response"].(map[string]any)
	}
	if st["status"] != "Partial" || st["importStatus"] != "Finished" {
		t.Fatalf("state %v", st)
	}
	_, env = call(t, h, key, "POST", "/rest/analysis", map[string]any{"type": "vuln", "sourceType": "individual", "scanID": rid,
		"query": map[string]any{"tool": "sumip", "startOffset": 0, "endOffset": 50}})
	if got := env["response"].(map[string]any)["totalRecords"]; got != "1" {
		t.Fatalf("hosts in a partial result %v, want the first half", got)
	}
}
