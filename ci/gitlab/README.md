# GitLab CI Templates for OpenCTEM Agent

This directory contains GitLab CI templates for integrating OpenCTEM security scanning into your pipelines.

## Quick Start

Add the following to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/openctemio/agent/main/ci/gitlab/openctem-security.yml'

stages:
  - build
  - security
  - deploy

# SAST scanning
sast:
  extends: .openctem-sast

# Dependency scanning (SCA)
dependency_scanning:
  extends: .openctem-sca

# Secret detection
secret_detection:
  extends: .openctem-secrets
```

## Configuration

### Required Secrets (Settings > CI/CD > Variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | No* | API key for pushing results to platform |
| `API_URL` | No | API URL (default: https://api.openctem.io) |

\* `API_KEY` is optional. If not set, scans still run but results won't be pushed to platform (scan-only mode).

### Template Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PUSH` | `"true"` | Push results to platform. Set `"false"` for testing |
| `COMMENTS` | `"true"` | Post findings as MR comments |
| `FAIL_ON` | `"critical"` | Security gate threshold |
| `VERBOSE` | `"false"` | Enable verbose output |

**Example: Scan-only mode (no push)**

```yaml
sast:
  extends: .openctem-sast
  variables:
    PUSH: "false"  # Disable push for testing
    FAIL_ON: high
```

## Available Templates

### `.openctem-sast`

Static Application Security Testing using Semgrep.

```yaml
sast:
  extends: .openctem-sast
  variables:
    SAST_TOOL: semgrep    # Tool to use (default: semgrep)
    FAIL_ON: high         # Block on high+ severity (default: critical)
    VERBOSE: "true"       # Enable verbose output
```

### `.openctem-sca`

Software Composition Analysis using Trivy.

```yaml
dependency_scanning:
  extends: .openctem-sca
  variables:
    SCA_TOOL: trivy       # Tool to use (default: trivy)
    FAIL_ON: high
```

### `.openctem-secrets`

Secret detection using Gitleaks.

```yaml
secret_detection:
  extends: .openctem-secrets
  variables:
    SECRET_TOOL: gitleaks # Tool to use (default: gitleaks)
    FAIL_ON: high
```

### `.openctem-container`

Container image scanning using Trivy.

```yaml
container_scanning:
  extends: .openctem-container
  variables:
    CONTAINER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    FAIL_ON: critical
```

### `.openctem-iac`

Infrastructure as Code scanning using Trivy.

```yaml
iac_scanning:
  extends: .openctem-iac
  variables:
    IAC_TOOL: trivy-config
    FAIL_ON: high
```

### `.openctem-full-scan`

All-in-one security scan (SAST + Secrets + SCA).

```yaml
security:
  extends: .openctem-full-scan
  variables:
    FAIL_ON: high
```

## Severity Thresholds

The `FAIL_ON` variable controls when the pipeline should fail:

| Value | Blocks on |
|-------|-----------|
| `critical` | Critical findings only |
| `high` | High and Critical |
| `medium` | Medium, High, and Critical |
| `low` | All findings |

## GitLab Security Dashboard

All templates generate SARIF output compatible with GitLab's Security Dashboard. The reports appear automatically in:
- Merge Request widget
- Pipeline Security tab
- Project Security Dashboard

## Example: Complete Pipeline

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/openctemio/agent/main/ci/gitlab/openctem-security.yml'

stages:
  - build
  - security
  - deploy

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

sast:
  extends: .openctem-sast
  variables:
    FAIL_ON: high

dependency_scanning:
  extends: .openctem-sca
  variables:
    FAIL_ON: high

secret_detection:
  extends: .openctem-secrets
  variables:
    FAIL_ON: critical

container_scanning:
  extends: .openctem-container
  variables:
    FAIL_ON: critical
  needs:
    - build

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
  needs:
    - sast
    - dependency_scanning
    - secret_detection
    - container_scanning
  only:
    - main
```

## Troubleshooting

### Results not appearing in platform

1. Check that `API_KEY` is set correctly
2. Enable verbose mode: `VERBOSE: "true"`
3. Check job logs for error messages

### Pipeline failing unexpectedly

1. Check the severity threshold (`FAIL_ON`)
2. Review findings in the job artifacts
3. Consider using `allow_failure: true` for initial rollout

### Scanner not finding issues

1. Verify the scanner is appropriate for your language/framework
2. Check excluded paths in scanner configuration
3. Run locally with verbose mode to debug
