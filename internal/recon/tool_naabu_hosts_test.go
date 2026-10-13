package recon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sensor/internal/toolrun"
)

// A discover.hosts@1 job runs naabu as host discovery, on the direct path
// and out of process alike: the report holds each answering address as a
// live ip_address with the probe that answered.
func TestNaabuHostDiscoveryJob(t *testing.T) {
	withSensorResolver(t)
	for _, runtime := range []string{"in-process", ""} {
		t.Run("runtime="+runtime, func(t *testing.T) {
			t.Setenv(toolrun.EnvRuntime, runtime)
			res, err := naabuScanner(t).ScanTargets(context.Background(), []string{"127.0.0.1"},
				&core.ScanOptions{Capability: "discover.hosts@1"})
			if err != nil {
				t.Fatal(err)
			}
			var rep struct {
				Assets []struct {
					Type       string         `json:"type"`
					Value      string         `json:"value"`
					Properties map[string]any `json:"properties"`
				} `json:"assets"`
			}
			if err := json.Unmarshal(res.RawOutput, &rep); err != nil {
				t.Fatal(err)
			}
			if len(rep.Assets) != 1 || rep.Assets[0].Type != "ip_address" || rep.Assets[0].Value != "127.0.0.1" ||
				rep.Assets[0].Properties["live_by"] != "tcp:5432" {
				t.Fatalf("assets = %+v", rep.Assets)
			}
		})
	}
}
