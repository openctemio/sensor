# OpenCTEM Agent

Open-source security scanning agent for Continuous Threat Exposure Management (CTEM).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://golang.org/)

## Overview

OpenCTEM Agent is a lightweight, extensible security scanning agent that integrates with the OpenCTEM platform. It supports multiple scanning tools and can run in various modes.

## Features

- **Multi-tool Support**: Semgrep, Trivy, Nuclei, Gitleaks, and more
- **SARIF Output**: Standard security results format
- **Flexible Modes**: One-shot, daemon, and standalone
- **CI/CD Integration**: Pre-built workflows for GitHub Actions and GitLab CI
- **Container Support**: Docker images for all supported tools

## Supported Tools

| Tool | Category | Description |
|------|----------|-------------|
| Semgrep | SAST | Static code analysis |
| Trivy | SCA/Container | Vulnerability scanning |
| Nuclei | DAST | Template-based scanning |
| Nuclei (validate) | Validation | Non-destructive re-verification of a finding's own template (CTEM Stage-4) |
| Gitleaks | Secrets | Secret detection |
| Naabu | Recon | Port scanning |
| Subfinder | Recon | Subdomain enumeration |
| HTTPx | Recon | HTTP probing |
| DNSx | Recon | DNS enumeration |
| Katana | Recon | Web crawling |

## Quick Start

### Installation

```bash
# From source
git clone https://github.com/openctemio/agent.git
cd agent
go build -o agent .

# Or download binary
curl -sSL https://github.com/openctemio/agent/releases/latest/download/agent-linux-amd64 -o agent
chmod +x agent
```

### Usage

#### One-shot Mode
```bash
# Run single scan and push results
./agent -tool semgrep -target ./src -push

# Run with specific tool
./agent -tool trivy -target ./

# Output to file
./agent -tool gitleaks -target ./ -output results.sarif
```

#### Daemon Mode
```bash
# Run as daemon, polling for jobs
./agent -daemon -config agent.yaml
```

#### Standalone Mode
```bash
# Run locally without API connection
./agent -standalone -tool nuclei -target https://example.com
```

### Docker

```bash
# Build image
docker build -t openctemio/agent .

# Run scan
docker run -v $(pwd):/target openctemio/agent -tool semgrep -target /target
```

## CI/CD Integration

### GitHub Actions
```yaml
- uses: openctemio/agent-action@v1
  with:
    tool: semgrep
    target: ./src
    api-url: ${{ secrets.OPENCTEM_API_URL }}
    api-key: ${{ secrets.OPENCTEM_API_KEY }}
```

### GitLab CI
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/openctemio/agent/main/ci/gitlab/semgrep.yml'
```

See [ci/](ci/) for more examples.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_URL` | Backend API base URL (or `-api-url` flag) | - |
| `API_KEY` | API authentication key (or `-api-key` flag) | - |
| `AGENT_ID` | Agent identifier (or `-agent-id` flag) | auto |
| `REGION` | Deployment region (or `-region` flag) | `default` |
| `AGENT_ALLOW_PRIVATE_TARGETS` | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. IMDS / loopback / CGNAT stay blocked regardless. See [Scanner safety model](#scanner-safety-model). | off |

### Config File (agent.yaml)

Keys map 1:1 to the parsed `config.Config` struct (`internal/config`): top-level
`agent:`, `api:`, and `executors:`.

```yaml
agent:
  name: production-scanner
  region: default
  max_jobs: 5

api:
  base_url: https://api.openctem.io
  api_key: your-api-key
  agent_id: your-agent-id

executors:
  vulnscan:
    enabled: true
    tools:
      nuclei: true
      trivy: true
      semgrep: true
  recon:
    enabled: true
    tools:
      subfinder: true
      dnsx: true
      naabu: true
      httpx: true
      katana: true
  secrets:
    enabled: false
    tools:
      gitleaks: true
      trufflehog: true
```

The persistent retry queue is enabled with the `-retry-queue` flag or
`RETRY_QUEUE=true` (directory via `-retry-dir` / `RETRY_DIR`), not through this file.

## Validation (CTEM Stage-4)

Beyond one-shot scanning, the daemon can **re-verify existing findings** so the
platform can confirm-or-downgrade them without a full rescan.

- **`validate`** — advertised **always**. The daemon wraps its command executor
  with a validating executor that runs a non-intrusive TCP-reachability
  safe-check for `validate` commands, regardless of which scanners are enabled
  (`platform.go buildCapabilities`).
- **`validate:nuclei`** — advertised when the vuln-scan (nuclei) image is present
  (`VulnScanEnabled`). It re-runs a finding's **own** detection template
  non-destructively and returns `detected` / `not_detected` / `inconclusive` /
  `error` (`internal/executor/validation.go` `RunNucleiValidate`). If the
  template is not installed, the result is `inconclusive` — never a false
  downgrade.

## Scanner safety model

Scan and validation targets originate from ingested asset data, so every target
passes an SSRF guard before any tool runs
(`internal/executor/target_security.go`):

- **Hard-blocked, never openable:** cloud metadata / link-local
  (`169.254.0.0/16`, incl. IMDS `169.254.169.254`), loopback (`127.0.0.0/8`,
  `::1`), and carrier-grade NAT (`100.64.0.0/10`), plus multicast/broadcast.
- **Blocked by default, opt-in:** RFC1918 / IPv6 ULA private space
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Set
  `AGENT_ALLOW_PRIVATE_TARGETS=1` to scan on-prem/internal targets. IMDS,
  loopback, and CGNAT stay blocked regardless.

Additional guards on the vuln-scan path:

- **Dangerous-flag blocklist** (`vulnscan.go validateExtraArgs`, CWE-77) — rejects
  user-supplied tool flags that redirect output, set a proxy, load an
  attacker-controlled target list / rule / template file, enable a headless
  browser, or override resolvers / interface / source IP.
- **Nuclei re-verify is detection-only** — the `dos`, `fuzz`, `intrusive`, and
  `brute-force` template tags are excluded, the template must have a safe
  matcher, runs are bounded by timeout and rate-limited per asset, and every run
  is logged under its command id (the audit key).

## Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Related Projects

- [openctemio/api](https://github.com/openctemio/api) - Backend API
- [openctemio/ui](https://github.com/openctemio/ui) - Web UI
- [openctemio/sdk](https://github.com/openctemio/sdk-go) - Go SDK

## License

Apache License 2.0 - see [LICENSE](LICENSE).
