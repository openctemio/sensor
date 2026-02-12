# OpenCTEM Agent CI/CD Templates

This directory contains CI/CD templates for integrating OpenCTEM security scanning into your pipelines.

## Supported Platforms

| Platform | Directory | Documentation |
|----------|-----------|---------------|
| GitHub Actions | [github/](github/) | [GitHub README](github/README.md) |
| GitLab CI | [gitlab/](gitlab/) | [GitLab README](gitlab/README.md) |

## Quick Comparison

| Feature | GitHub Actions | GitLab CI |
|---------|----------------|-----------|
| Reusable workflow | `openctem-security.yml` | `openctem-security.yml` |
| Parallel execution | `parallel-security.yml` | `parallel-security.yml` |
| Composite action | `action.yml` | N/A (uses extends) |
| Security dashboard | GitHub Security tab | GitLab Security Dashboard |
| SARIF support | Native | Native |

## Common Configuration

Both platforms support these configuration variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PUSH` | `"true"` | Push results to OpenCTEM platform |
| `COMMENTS` | `"true"` | Post findings as PR/MR comments |
| `FAIL_ON` | `"critical"` | Security gate threshold |
| `VERBOSE` | `"false"` | Enable verbose output |

### Smart Defaults

- If `PUSH` is enabled but `API_KEY` is not set, push is automatically disabled
- This allows testing CI integration without platform credentials (scan-only mode)

## Security Gate

The `FAIL_ON` variable controls when the pipeline should fail:

| Value | Blocks on |
|-------|-----------|
| `critical` | Critical findings only |
| `high` | High and Critical |
| `medium` | Medium, High, and Critical |
| `low` | All findings |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass - no findings above threshold |
| 1 | Fail - findings above threshold |
| 2 | Error - configuration or runtime error |

## Tool Update Mechanism

| Tool | Update Method | Frequency |
|------|---------------|-----------|
| Semgrep | Rules fetched from Registry | Every scan |
| Trivy | DB auto-downloads | Every 6 hours |
| Gitleaks | Rules embedded in binary | On image update |
| Nuclei | Templates auto-update | On first run |

## More Information

- [Agent Usage Guide](https://docs.openctem.io/guides/agent-usage)
- [CI/CD Integration](https://docs.openctem.io/guides/agent-usage#cicd-integration)
- [Docker Images](https://hub.docker.com/r/openctemio/agent)
