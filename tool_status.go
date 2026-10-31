package main

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sensor/internal/tools"
)

// toolProbeTimeout bounds one `<tool> --version` run.
const toolProbeTimeout = 30 * time.Second

// probeTool reports whether a scanner's binary is available here, missing,
// or installed but failing to run.
func probeTool(scanner string) tools.Status {
	ctx, cancel := context.WithTimeout(context.Background(), toolProbeTimeout)
	defer cancel()
	return tools.Probe(ctx, tools.BinaryFor(scanner))
}

// unavailableReason explains why a configured scanner cannot be used. A
// binary that is missing and one that is installed but fails to run are
// different problems: the second one is a broken image or host and is
// reported with the tool's own error output, so it is never mistaken for an
// optional tool that simply is not there.
func unavailableReason(ctx context.Context, cfg ScannerConfig, checkErr error) string {
	binary := cfg.Binary
	if binary == "" {
		binary = tools.BinaryFor(cfg.Name)
	}
	pctx, cancel := context.WithTimeout(ctx, toolProbeTimeout)
	defer cancel()
	st := tools.Probe(pctx, binary)
	switch st.State {
	case tools.NotInstalled:
		return fmt.Sprintf("not installed (%v)", st.Err)
	case tools.Broken:
		return fmt.Sprintf("installed but fails to run: %v", st.Err)
	default:
		// `--version` works, but the scanner's own check failed.
		if checkErr != nil {
			return fmt.Sprintf("installed (%s) but its check failed: %v", st.Version, checkErr)
		}
		return fmt.Sprintf("installed (%s) but its check failed", st.Version)
	}
}

// daemonCredentialsHelp words the SDK's error for a server-controlled daemon
// started without the platform URL or API key (sensorkit.CheckCredentials).
var daemonCredentialsHelp = sensorkit.CredentialsHelp{
	Subject: "the daemon (the default mode, which takes platform commands)",
	Hint: "  Set SENSOR_API_URL (docker run -e SENSOR_API_URL=https://<platform>/ ..., -api-url, or api.base_url in the -config file).\n" +
		"  Without SENSOR_API_KEY the sensor pairs on first start: it prints a link, a code and a fingerprint\n" +
		"  for an administrator to approve in the console (SENSOR_PAIRING_CODE: pair under a code from the\n" +
		"  console's install command; or run `openctemio-sensor pair` first). A shared sensor of the instance\n" +
		"  is enrolled with SENSOR_INSTANCE_ENROLLMENT_TOKEN, the single-use token a super administrator issued.\n" +
		"  To scan without a platform, run a one-shot scan instead: -tool <name> -target <path>",
}
