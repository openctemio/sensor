//go:build platform

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	apiclient "github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// In-process verification of the platform result-push path that #20 wired up
// (previously the executors got a nil pusher and silently dropped every
// finding/asset). This stands in for live-cluster QA: it drives a real
// platformResultPusher against a fake ingest server and asserts that PushCTIS
// actually delivers findings AND assets to /api/v1/agent/ingest.
func TestPlatformResultPusher_PushCTIS_DeliversToIngest(t *testing.T) {
	type ingestBody struct {
		Findings []ctis.Finding `json:"findings"`
		Assets   []ctis.Asset   `json:"assets"`
	}

	var (
		mu             sync.Mutex
		ingestCalls    int
		findingsPushed int
		assetsPushed   int
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/ingest" {
			t.Errorf("unexpected path %q (want /api/v1/agent/ingest)", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body ingestBody
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		ingestCalls++
		findingsPushed += len(body.Findings)
		assetsPushed += len(body.Assets)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(apiclient.IngestResponse{
			ScanID:          "scan-test",
			FindingsCreated: len(body.Findings),
			AssetsCreated:   len(body.Assets),
		})
	}))
	defer server.Close()

	pusher := &platformResultPusher{
		client: apiclient.New(&apiclient.Config{
			BaseURL: server.URL,
			APIKey:  "test-key",
			AgentID: "agent-test",
		}),
	}

	report := &ctis.Report{
		Version: "1.0",
		Findings: []ctis.Finding{
			{ID: "f1", Type: ctis.FindingTypeVulnerability, Title: "Test", Severity: ctis.SeverityHigh},
		},
		Assets: []ctis.Asset{
			{ID: "a1", Type: ctis.AssetTypeRepository, Value: "github.com/org/repo"},
		},
	}

	if err := pusher.PushCTIS(context.Background(), report); err != nil {
		t.Fatalf("PushCTIS returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// PushCTIS calls both PushFindings and PushAssets with the full report, so
	// there are 2 ingest calls and assets are carried in both (ingest is
	// fingerprint-idempotent, so the repeat is harmless). The point under test
	// is that findings AND assets actually reach ingest — pre-#20 the pusher
	// was nil and nothing was delivered.
	if ingestCalls != 2 {
		t.Errorf("expected 2 ingest calls (findings + assets), got %d", ingestCalls)
	}
	if findingsPushed < 1 {
		t.Errorf("expected findings delivered to ingest, got %d", findingsPushed)
	}
	if assetsPushed < 1 {
		t.Errorf("expected assets delivered to ingest, got %d", assetsPushed)
	}
}

// A nil/empty report must be a no-op (no ingest calls), not a panic or a
// spurious request.
func TestPlatformResultPusher_PushCTIS_EmptyIsNoop(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	pusher := &platformResultPusher{
		client: apiclient.New(&apiclient.Config{BaseURL: server.URL, APIKey: "k", AgentID: "a"}),
	}

	if err := pusher.PushCTIS(context.Background(), nil); err != nil {
		t.Fatalf("nil report: %v", err)
	}
	if err := pusher.PushCTIS(context.Background(), &ctis.Report{Version: "1.0"}); err != nil {
		t.Fatalf("empty report: %v", err)
	}
	if calls != 0 {
		t.Errorf("empty/nil report must not hit ingest, got %d calls", calls)
	}
}
