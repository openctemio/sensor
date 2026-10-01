# OpenCTEM Sensor

Open-source security scanning sensor for Continuous Threat Exposure Management (CTEM).
Formerly the *OpenCTEM Agent*: see [Upgrading from the agent release](#upgrading-from-the-agent-release).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://golang.org/)

## Overview

The OpenCTEM sensor (`openctemio-sensor`) is a lightweight, extensible security scanning sensor that integrates with the OpenCTEM platform. It supports multiple scanning tools and can run in various modes.

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
go build -o openctemio-sensor .

# Or download a release archive
curl -sSL https://github.com/openctemio/agent/releases/download/<version>/openctemio-sensor_<version>_linux_amd64.tar.gz | tar xz
chmod +x openctemio-sensor
```

### Usage

#### One-shot Mode
```bash
# Run single scan and push results
./openctemio-sensor -tool semgrep -target ./src -push

# Run with specific tool
./openctemio-sensor -tool trivy -target ./

# Output to file
./openctemio-sensor -tool gitleaks -target ./ -output results.sarif
```

#### Daemon Mode
```bash
# Run as daemon, polling for jobs
./openctemio-sensor -daemon -config sensor.yaml
```

#### Standalone Mode
```bash
# Run locally without API connection
./openctemio-sensor -standalone -tool nuclei -target https://example.com
```

### Docker

```bash
# Build image
docker build -t openctemio/sensor .

# Run scan
docker run -v $(pwd):/target openctemio/sensor -tool semgrep -target /target
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
| `SENSOR_ID` | Sensor identifier (or `-sensor-id` flag) | auto |
| `SENSOR_NAME` | Platform-mode sensor name (or `-name` flag) | auto |
| `REGION` | Deployment region (or `-region` flag) | `default` |
| `SENSOR_ALLOW_PRIVATE_TARGETS` | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. IMDS / loopback / CGNAT stay blocked regardless. See [Scanner safety model](#scanner-safety-model). | off |

`API_URL`, `API_KEY` and `BOOTSTRAP_TOKEN` keep their names. The pre-rename
names `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` and `-agent-id`
still work (see [Upgrading](#upgrading-from-the-agent-release)).

### Config File (sensor.yaml)

`-config` reads the keys of `Config` in `main.go`: `sensor:`, `server:`,
`retry_queue:`, `scanners:`, `collectors:` and `targets:`.

```yaml
sensor:
  name: production-scanner
  region: default
  heartbeat_interval: 1m
  enable_commands: true
  command_poll_interval: 30s

server:
  base_url: https://api.openctem.io
  api_key: ${API_KEY}
  sensor_id: your-sensor-id
  timeout: 30s

scanners:
  - name: semgrep
    enabled: true
  - name: gitleaks
    enabled: true

targets:
  - /path/to/project
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
  `SENSOR_ALLOW_PRIVATE_TARGETS=1` to scan on-prem/internal targets. IMDS,
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

## Upgrading from the agent release

The binary, images and settings were renamed from *agent* to *sensor*
([RFC-023 §9.5](https://github.com/openctemio/api/blob/develop/docs/rfcs/RFC-023-scan-zones-and-scanners.md)).
A sensor upgraded in place keeps working with its existing configuration:

| Before | After | On upgrade |
|---|---|---|
| binary `agent` | `openctemio-sensor` | — |
| image `ghcr.io/openctemio/agent:<tag>` | `ghcr.io/openctemio/sensor:<tag>` | old tags stay pullable and frozen (never updated, never deleted) |
| `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` | `SENSOR_ID`, `SENSOR_NAME`, `SENSOR_ALLOW_PRIVATE_TARGETS` | old name applied, startup warning naming both |
| `-agent-id` | `-sensor-id` | old flag applied, startup warning |
| config `agent:` block, `server.agent_id` | `sensor:`, `server.sensor_id` | old keys applied, startup warning |
| `~/.openctem/agent-credentials.json` | `~/.openctem/sensor-credentials.json` | moved on first start (written 0600 and read back before the old file is removed); same identity and key, no re-registration. If the file cannot be moved (read-only mount) it is used in place. `-credentials <path>` is used as is. |
| `API_URL`, `API_KEY`, `BOOTSTRAP_TOKEN` | unchanged | — |

The sensor refuses to start only when an old and a new name are both set to
**different** values; the error names both (never the values). The wire to the
platform (protocol v1) is unchanged, so an upgraded sensor works with any
platform version.

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
