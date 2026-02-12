# OpenCTEM Agent

Open-source security scanning agent for Continuous Threat Exposure Management (CTEM).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25-blue?logo=go)](https://golang.org/)

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
| Gitleaks | Secrets | Secret detection |
| Nmap | Recon | Network discovery |
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
| `OPENCTEM_API_URL` | Backend API URL | http://localhost:8080 |
| `OPENCTEM_API_KEY` | API authentication key | - |
| `OUTPUT_FORMAT` | Output format (sarif, json) | sarif |
| `LOG_LEVEL` | Logging level | info |

### Config File (agent.yaml)
```yaml
api:
  url: http://localhost:8080
  key: ${OPENCTEM_API_KEY}

daemon:
  interval: 60s
  tools:
    - semgrep
    - trivy

logging:
  level: info
  file: /var/log/agent.log
```

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
