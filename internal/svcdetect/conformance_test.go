package svcdetect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The detect.services conformance suite of sdk-go: the credential sentinel
// (no fixture receives an authentication payload), identification of SSH,
// Redis, MySQL, SMTP, HTTP and HTTPS, same-value output and output bounds.
// The standard params go through the manifest's mapping, as the sensor
// applies them.
func TestDetectServicesConformance(t *testing.T) {
	conformance.DetectServicesSuite(t, func(task tool.Task) (*ctis.Report, error) {
		mapped, err := Manifest.ApplyParams(task)
		if err != nil {
			return nil, err
		}
		var cfg Config
		if len(mapped.Config) > 0 {
			if err := json.Unmarshal(mapped.Config, &cfg); err != nil {
				return nil, err
			}
		}
		if cfg.Depth != DepthThorough || cfg.TimeoutMs != 1500 {
			t.Errorf("mapped config %+v", cfg)
		}
		local, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		task.Local, task.Params = local, nil
		res := testkit.Run(t, Tool, task, testkit.Options{Timeout: 90 * time.Second})
		res.RequireStatus(t, tool.StatusOK)
		return res.Report, nil
	})
}
