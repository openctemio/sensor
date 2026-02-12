# GitHub Actions for OpenCTEM Agent

This directory contains GitHub Actions workflows and composite actions for integrating OpenCTEM security scanning into your CI/CD pipelines.

## Quick Start

### Option 1: Reusable Workflow (Recommended)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    uses: openctemio/agent/.github/workflows/openctem-security.yml@main
    with:
      tools: "semgrep,gitleaks,trivy"
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
    uses: openctemio/agent/.github/workflows/parallel-security.yml@main
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
      - uses: openctemio/agent/ci/github@main
        with:
          tools: semgrep,gitleaks,trivy
          fail_on: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          API_URL: ${{ secrets.API_URL }}
          API_KEY: ${{ secrets.API_KEY }}
```

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
| `tools` | `"semgrep,gitleaks,trivy"` | Comma-separated list of tools |
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
| `full` | semgrep + gitleaks + trivy | All CI tools in one job |
| `sast` | semgrep | Static Application Security Testing |
| `sca` | trivy | Software Composition Analysis |
| `secrets` | gitleaks | Secret detection |
| `iac` | trivy-config | Infrastructure as Code |
| `container` | trivy-image | Container image scanning |
| `dast` | nuclei | Dynamic Application Security Testing |

> **Note**: DAST requires a running application and should run in a separate workflow after deployment, not during PR checks.

## Docker Images

| Image | Size | Tools | Use Case |
|-------|------|-------|----------|
| `openctemio/agent:ci` | ~600MB | semgrep + gitleaks + trivy | Full CI pipeline |
| `openctemio/agent:semgrep` | ~400MB | Semgrep only | SAST scanning |
| `openctemio/agent:gitleaks` | ~50MB | Gitleaks only | Secrets detection |
| `openctemio/agent:trivy` | ~100MB | Trivy only | SCA/IaC/Container |
| `openctemio/agent:nuclei` | ~100MB | Nuclei only | DAST scanning |

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

- [Agent Usage Guide](https://docs.openctem.io/guides/agent-usage)
- [CI/CD Integration](https://docs.openctem.io/guides/agent-usage#cicd-integration)
