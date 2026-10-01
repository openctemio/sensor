# Sensor Quick Start Guide

Get your first security scan running in **5 minutes**.

---

## What is the OpenCTEM sensor?

The OpenCTEM sensor (`openctemio-sensor`, formerly the OpenCTEM Agent) is a **command-line security scanner** that runs tools like Semgrep, Gitleaks, and Trivy, then pushes results to the OpenCTEM platform.

**Use Cases:**
- 🏃 **CI/CD Pipelines** - One-shot scans in GitHub Actions, GitLab CI
- 🖥️ **Production Scanning** - Server-controlled daemon mode
- 🔄 **Scheduled Scans** - Periodic scanning of code repositories

---

## Installation

### Option 1: Binary (Recommended)

**Linux (amd64):**
```bash
curl -sSL https://github.com/openctemio/agent/releases/latest/download/openctemio-sensor_linux_amd64.tar.gz | tar xz
sudo mv openctemio-sensor /usr/local/bin/
openctemio-sensor --version
```

**macOS (Apple Silicon):**
```bash
curl -sSL https://github.com/openctemio/agent/releases/latest/download/openctemio-sensor_darwin_arm64.tar.gz | tar xz
sudo mv openctemio-sensor /usr/local/bin/
openctemio-sensor --version
```

### Option 2: Docker

```bash
docker pull ghcr.io/openctemio/sensor:latest-default
```

### Option 3: Go Install

```bash
go install github.com/openctemio/agent@latest
```

---

## First Scan (5 Minutes)

### Step 1: Get API Key

1. Login to OpenCTEM UI at [http://localhost:3000](http://localhost:3000)
2. Navigate to **Settings → Sensors**
3. Click **"Create Sensor"**
4. Choose type: **Runner** (for CI/CD)
5. **Copy the API Key**

---

### Step 2: Set Environment Variables

```bash
export API_URL=http://localhost:8080
export API_KEY=your-api-key-here
```

For production, use your deployed API URL (e.g., `https://api.openctem.io`).

---

### Step 3: Run a Scan

Navigate to your code directory and run:

```bash
openctemio-sensor -tools semgrep,gitleaks,trivy -target . -push -verbose
```

**What this does:**
- **semgrep** - Scans for code vulnerabilities (SAST)
- **gitleaks** - Detects exposed secrets
- **trivy** - Finds package vulnerabilities (SCA)
- **-push** - Sends results to OpenCTEM platform
- **-verbose** - Shows detailed logs

---

### Step 4: View Results

1. Go to **Findings** in the OpenCTEM UI
2. Filter by your repository or sensor
3. Review detected vulnerabilities
4. Assign and remediate

---

## Common Use Cases

### Use Case 1: CI/CD Pipeline (GitHub Actions)

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: docker://openctemio/sensor:ci
        env:
          API_URL: ${{ secrets.OPENCTEM_API_URL }}
          API_KEY: ${{ secrets.OPENCTEM_API_KEY }}
        with:
          args: -tools semgrep,gitleaks,trivy -target . -push -comments
```

**Secrets to set:**
- `OPENCTEM_API_URL` - Your API URL
- `OPENCTEM_API_KEY` - Sensor API key

---

### Use Case 2: Scheduled Scanning (Daemon Mode)

Create `sensor.yaml`:

```yaml
sensor:
  name: production-scanner
  region: default
  heartbeat_interval: 1m
  enable_commands: true

server:
  base_url: https://api.openctem.io
  api_key: ${API_KEY}
  sensor_id: your-sensor-id

scanners:
  - name: semgrep
    enabled: true
  - name: gitleaks
    enabled: true

targets:
  - /path/to/project
```

> `-config` reads the keys of `Config` in `main.go`: `sensor:`, `server:`,
> `retry_queue:`, `scanners:`, `collectors:`, `targets:`. Files written for
> the agent release (`agent:` block, `server.agent_id`) still load, with a
> deprecation warning. The retry queue is enabled with the
> `-retry-queue` flag or `RETRY_QUEUE=true`.

Run the daemon:

```bash
openctemio-sensor -daemon -config sensor.yaml -retry-queue
```

The sensor will:
1. Connect to the platform
2. Poll for scan commands from the server
3. Execute scans automatically
4. Send heartbeats

---

### Use Case 3: Docker One-Shot Scan

```bash
docker run --rm \
  -v "$(pwd)":/scan \
  -e API_URL=https://api.openctem.io \
  -e API_KEY=your-api-key \
  ghcr.io/openctemio/sensor:latest-default \
  -tools semgrep,gitleaks,trivy -target /scan -push
```

---

## Available Scanners

| Tool | Type | Description |
|------|------|-------------|
| `semgrep` | SAST | Code analysis with taint tracking |
| `gitleaks` | Secret | Secret and credential detection |
| `trivy-fs` | SCA | Filesystem vulnerability scanning |
| `trivy-config` | IaC | Infrastructure misconfiguration |
| `trivy-image` | Container | Container image scanning |
| `trivy-full` | All | Vuln + misconfig + secret |

**Check installed tools:**
```bash
openctemio-sensor -check-tools
```

**Install missing tools:**
```bash
openctemio-sensor -install-tools
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `API_URL` | Yes* | Platform API URL |
| `API_KEY` | Yes* | API key for authentication |
| `SENSOR_ID` | No | Sensor identifier (auto-generated if not set; `AGENT_ID` still read) |
| `REGION` | No | Deployment region (e.g., `us-east-1`) |
| `SENSOR_ALLOW_PRIVATE_TARGETS` | No | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. Default off. IMDS / loopback / CGNAT stay blocked regardless. See [security hardening guide](../../docs/operations/security-hardening.md#agent-private-target-opt-in). |

*Required when using `-push` flag or daemon mode

> **On-prem scanning:** if your sensor runs inside a corporate network and scans services on `10.x` / `192.168.x` / `172.16-31.x`, set `SENSOR_ALLOW_PRIVATE_TARGETS=1` (`AGENT_ALLOW_PRIVATE_TARGETS=1` still works). Without it, the sensor refuses private-IP targets to prevent SSRF.

### Command-Line Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-tool` | Single scanner | `-tool semgrep` |
| `-tools` | Multiple scanners | `-tools semgrep,gitleaks,trivy` |
| `-target` | Scan target path | `-target /path/to/code` |
| `-push` | Push results to platform | `-push` |
| `-verbose` | Detailed logs | `-verbose` |
| `-daemon` | Run as daemon | `-daemon` |
| `-config` | Config file path | `-config sensor.yaml` |
| `-comments` | Post PR/MR comments | `-comments` |

---

## Troubleshooting

### Problem: "Tool not found"

**Solution:**
```bash
# Check which tools are installed
openctemio-sensor -check-tools

# Install missing tools
openctemio-sensor -install-tools
```

---

### Problem: "Connection refused"

**Checklist:**
1. Verify `API_URL` is correct: `echo $API_URL`
2. Check API is running: `curl $API_URL/health`
3. Check firewall rules
4. For Docker, use `host.docker.internal` on Mac/Windows

**Example:**
```bash
# On Mac/Windows with Docker Desktop
export API_URL=http://host.docker.internal:8080
```

---

### Problem: "Authentication failed"

**Checklist:**
1. Verify API key: `echo $API_KEY`
2. Check the sensor is registered in the UI
3. Ensure the sensor type matches usage (Runner vs Worker)

---

### Problem: "No findings found"

**Possible causes:**
- Code is clean (good news!)
- Scanner rules not matching
- Scanner not installed

**Debug:**
```bash
# Run with verbose logging
openctemio-sensor -tools semgrep -target . -verbose

# Check scanner output manually
semgrep --config auto .
```

---

## Next Steps

### Learn More

- **[Configuration Reference](./CONFIGURATION_REFERENCE.md)** - Full sensor.yaml reference
- **[Sensor README](../README.md)** - Complete documentation
- **[SDK Documentation](../../sdk/README.md)** - Build custom tools

### Advanced Topics

- **Retry Queue** - Network resilience for unreliable connections
- **Custom Scanners** - Integrate proprietary tools
- **Kubernetes Deployment** - Run sensors in K8s clusters

---

## Need Help?

- 📚 **Documentation:** [docs.openctem.io](https://docs.openctem.io)
- 💬 **Discord:** [discord.gg/openctemio](https://discord.gg/openctemio)
- 🐛 **Issues:** [GitHub Issues](https://github.com/openctemio/agent/issues)

---

**Happy scanning! 🔍**
