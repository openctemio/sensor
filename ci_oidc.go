package main

// Runner mode with CI workload identity (api RFC-051): in a GitHub Actions or
// GitLab CI job with OPENCTEM_TENANT_ID set, the sensor exchanges the job's
// OIDC token for a short-lived run token instead of using a stored API key,
// and asks the platform's gate for the verdict. The tokens are never printed.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/sensorkit"

	"github.com/openctemio/sensor/internal/gate"
)

// openCIRun returns the CI run of this job, or nil when the job offers no
// OIDC token (the sensor then uses API_KEY, if set). When the tenant is set
// but no token is available, it says why.
func openCIRun(apiURL string, stderr io.Writer, getenv func(string) string) *sensorkit.CIRun {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := sensorkit.CIRunConfig{APIURL: apiURL, TenantID: getenv(sensorkit.EnvTenantID),
		Audience: getenv(sensorkit.EnvOIDCAudience), IDTokenVar: getenv(sensorkit.EnvIDTokenVar), Getenv: getenv}
	run, err := sensorkit.NewCIRun(cfg)
	if err == nil {
		return run
	}
	if strings.TrimSpace(cfg.TenantID) != "" {
		if errors.Is(err, sensorkit.ErrNoCIOIDC) {
			_, _ = fmt.Fprintf(stderr, "Warning: %s is set but this job has no CI OIDC token "+
				"(GitHub Actions: grant 'permissions: id-token: write'; GitLab CI: define 'id_tokens: %s' with the trust configuration's audience)\n",
				sensorkit.EnvTenantID, nonEmptyStr(cfg.IDTokenVar, sensorkit.DefaultIDTokenVar))
		} else {
			_, _ = fmt.Fprintf(stderr, "Warning: CI runner mode is not available: %v\n", err)
		}
	}
	return nil
}

// inCI reports whether the process runs in a CI job.
func inCI(getenv func(string) string) bool {
	return getenv("CI") == "true" || getenv("GITHUB_ACTIONS") == "true" || getenv("GITLAB_CI") == "true"
}

// warnAPIKeyInCI says that a stored API key in CI is deprecated.
func warnAPIKeyInCI(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "Warning: authenticating a CI job with a stored API key is deprecated; "+
		"use the job's OIDC identity instead (set "+sensorkit.EnvTenantID+" and add a CI trust configuration; see Settings > Scanning > CI pipelines)")
}

// ciGateExit asks the platform's gate for the run's verdict and prints it.
// decided is false when the gate could not be reached and a local -fail-on
// threshold should decide instead (the offline fallback).
func ciGateExit(ctx context.Context, run *sensorkit.CIRun, scanFailures int, failOn string, stdout, stderr io.Writer) (code int, decided bool) {
	v, err := run.Evaluate(ctx, scanFailures)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Warning: the OpenCTEM gate could not be reached: %v\n", err)
		if failOn != "" {
			_, _ = fmt.Fprintf(stderr, "Falling back to the local gate (-fail-on %s)\n", failOn)
			return 0, false
		}
		return gate.ExitCodeError, true
	}
	sensorkit.WriteVerdict(stdout, v)
	if v.Failed() {
		return gate.ExitCodeFail, true
	}
	return gate.ExitCodePass, true
}

func nonEmptyStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
