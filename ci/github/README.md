# GitHub Actions for OpenCTEM Sensor

This directory contains GitHub Actions workflows and composite actions for integrating OpenCTEM security scanning into your CI/CD pipelines.

## Quick Start

### Option 1: Reusable Workflow (Recommended)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    uses: openctemio/sensor/.github/workflows/openctem-security.yml@main
    with:
      tools: "semgrep,betterleaks,trivy"
      fail_on: "high"
    secrets:
      api_url: ${{ secrets.API_URL }}
      api_key: ${{ secrets.API_KEY }}
```

### Option 2: Parallel Workflow (Fastest)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    uses: openctemio/sensor/.github/workflows/parallel-security.yml@main
    with:
      fail_on: "high"
    secrets:
      api_url: ${{ secrets.API_URL }}
      api_key: ${{ secrets.API_KEY }}
```

### Option 3: Composite Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openctemio/sensor/ci/github@main
        with:
          tools: semgrep,betterleaks,trivy
          fail_on: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          API_URL: ${{ secrets.API_URL }}
          API_KEY: ${{ secrets.API_KEY }}
```

### CI identity (no API key)

```yaml
jobs:
  security:
    uses: openctemio/sensor/.github/workflows/openctem-security.yml@main
    permissions:
      contents: read
      id-token: write
      pull-requests: write
      security-events: write
    with:
      tenant_id: "<your organization id>"
    secrets:
      api_url: ${{ secrets.API_URL }}
```

The job's OIDC token is exchanged for a 15-minute run token; the platform's gate
decides pass or fail. See [../README.md](../README.md#ci-identity-no-stored-api-key-recommended).

## Configuration

### Secrets (Repository Settings > Secrets)

| Secret | Required | Description |
|--------|----------|-------------|
| `API_KEY` | No* | API key for pushing results to platform |
| `API_URL` | No | API URL (default: https://api.openctem.io) |

\* `API_KEY` is optional. If not set, scans still run but results won't be pushed to platform (scan-only mode).

### Workflow Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `tools` | `"semgrep,betterleaks,trivy"` | Comma-separated list of tools |
| `scan_type` | `"full"` | Scan type: full, sast, sca, secrets, iac, container |
| `fail_on` | `"critical"` | Security gate threshold |
| `push` | `true` | Push results to platform |
| `comments` | `true` | Post findings as PR comments |
| `verbose` | `false` | Enable verbose output |
| `upload_sarif` | `true` | Upload SARIF to GitHub Security tab |

### Smart Defaults

- If `push` is `true` but `API_KEY` is not set, push is automatically disabled (scan-only mode)
- This allows testing CI integration without configuring platform credentials

## Available Workflows

| Workflow | Description |
|----------|-------------|
| `openctem-security.yml` | Single-job security scan with all tools |
| `parallel-security.yml` | Parallel jobs for SAST, Secrets, SCA (fastest) |

## Available Scan Types

| Scan Type | Tools | Description |
|-----------|-------|-------------|
| `full` | semgrep + betterleaks + trivy | All CI tools in one job |
| `sast` | semgrep | Static Application Security Testing |
| `sca` | trivy | Software Composition Analysis |
| `secrets` | betterleaks | Secret detection |
| `iac` | trivy-config | Infrastructure as Code |
| `container` | trivy-image | Container image scanning |
| `dast` | nuclei | Dynamic Application Security Testing |

> **Note**: DAST requires a running application and should run in a separate workflow after deployment, not during PR checks.

## Docker Images

Images are published to GHCR when a sensor release is tagged, as
`ghcr.io/openctemio/sensor:<version>-<variant>` (for example `v0.9.1-ci`) and
`ghcr.io/openctemio/sensor:latest-<variant>`, and signed with cosign. The
templates pin each image by digest and the composite action verifies the
signature before running it; see [Supply chain](../README.md#supply-chain-pinned-signed-images).
Do not use the `latest-*` tags in pipelines.

| Image | Size | Tools | Use Case |
|-------|------|-------|----------|
| `ghcr.io/openctemio/sensor:latest-ci` | ~600MB | semgrep + betterleaks + trivy | Full CI pipeline |
| `ghcr.io/openctemio/sensor:latest-semgrep` | ~400MB | Semgrep only | SAST scanning |
| `ghcr.io/openctemio/sensor:latest-betterleaks` | ~50MB | Betterleaks only | Secrets detection |
| `ghcr.io/openctemio/sensor:latest-trivy` | ~100MB | Trivy (vulnerability DB preloaded) | SCA/IaC/Container |
| `ghcr.io/openctemio/sensor:latest-nuclei` | ~100MB | Nuclei only | DAST scanning |

## Troubleshooting

### Results not appearing in platform

1. Check that `API_KEY` is set correctly in repository secrets
2. Enable verbose mode: `verbose: true`
3. Check job logs for error messages

### Pipeline failing unexpectedly

1. Check the severity threshold (`fail_on`)
2. Review findings in the Security tab
3. Consider using `fail_on: "critical"` for initial rollout

### SARIF not uploading

1. Ensure `upload_sarif: true` (default)
2. Check that the workflow has `security-events: write` permission
3. Verify SARIF file exists in job artifacts

## More Information

- [Sensor Usage Guide](https://docs.openctem.io/guides/agent-usage)
- [CI/CD Integration](https://docs.openctem.io/guides/agent-usage#cicd-integration)
