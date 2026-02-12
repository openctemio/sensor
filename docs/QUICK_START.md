# Agent Quick Start Guide

Get your first security scan running in **5 minutes**.

---

## What is the OpenCTEM Agent?

The OpenCTEM Agent is a **command-line security scanner** that runs tools like Semgrep, Gitleaks, and Trivy, then pushes results to the OpenCTEM platform.

**Use Cases:**
- 🏃 **CI/CD Pipelines** - One-shot scans in GitHub Actions, GitLab CI
- 🖥️ **Production Scanning** - Server-controlled daemon mode
- 🔄 **Scheduled Scans** - Periodic scanning of code repositories

---

## Installation

### Option 1: Binary (Recommended)

**Linux (amd64):**
```bash
curl -sSL https://github.com/openctemio/agent/releases/latest/download/agent_linux_amd64.tar.gz | tar xz
sudo mv agent /usr/local/bin/
agent --version
```

**macOS (Apple Silicon):**
```bash
curl -sSL https://github.com/openctemio/agent/releases/latest/download/agent_darwin_arm64.tar.gz | tar xz
sudo mv agent /usr/local/bin/
agent --version
```

### Option 2: Docker

```bash
docker pull openctemio/agent:latest
```

### Option 3: Go Install

```bash
go install github.com/openctemio/agent@latest
```

---

## First Scan (5 Minutes)

### Step 1: Get API Key

1. Login to OpenCTEM UI at [http://localhost:3000](http://localhost:3000)
2. Navigate to **Settings → Agents**
3. Click **"Create Agent"**
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
agent -tools semgrep,gitleaks,trivy -target . -push -verbose
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
2. Filter by your repository or agent
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
        uses: docker://openctemio/agent:ci
        env:
          API_URL: ${{ secrets.OPENCTEM_API_URL }}
          API_KEY: ${{ secrets.OPENCTEM_API_KEY }}
        with:
          args: -tools semgrep,gitleaks,trivy -target . -push -comments
```

**Secrets to set:**
- `OPENCTEM_API_URL` - Your API URL
- `OPENCTEM_API_KEY` - Agent API key

---

### Use Case 2: Scheduled Scanning (Daemon Mode)

Create `agent.yaml`:

```yaml
agent:
  name: production-scanner
  enable_commands: true
  command_poll_interval: 30s
  heartbeat_interval: 1m

server:
  base_url: https://api.openctem.io
  api_key: your-api-key
  agent_id: your-agent-id

scanners:
  - name: semgrep
    enabled: true
  - name: gitleaks
    enabled: true
  - name: trivy-fs
    enabled: true

retry_queue:
  enabled: true
  interval: 5m
```

Run the daemon:

```bash
agent -daemon -config agent.yaml
```

The agent will:
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
  openctemio/agent:latest \
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
agent -check-tools
```

**Install missing tools:**
```bash
agent -install-tools
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `API_URL` | Yes* | Platform API URL |
| `API_KEY` | Yes* | API key for authentication |
| `AGENT_ID` | No | Agent identifier (auto-generated if not set) |
| `REGION` | No | Deployment region (e.g., `us-east-1`) |

*Required when using `-push` flag or daemon mode

### Command-Line Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-tool` | Single scanner | `-tool semgrep` |
| `-tools` | Multiple scanners | `-tools semgrep,gitleaks,trivy` |
| `-target` | Scan target path | `-target /path/to/code` |
| `-push` | Push results to platform | `-push` |
| `-verbose` | Detailed logs | `-verbose` |
| `-daemon` | Run as daemon | `-daemon` |
| `-config` | Config file path | `-config agent.yaml` |
| `-comments` | Post PR/MR comments | `-comments` |

---

## Troubleshooting

### Problem: "Tool not found"

**Solution:**
```bash
# Check which tools are installed
agent -check-tools

# Install missing tools
agent -install-tools
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
2. Check agent is registered in UI
3. Ensure agent type matches usage (Runner vs Worker)

---

### Problem: "No findings found"

**Possible causes:**
- Code is clean (good news!)
- Scanner rules not matching
- Scanner not installed

**Debug:**
```bash
# Run with verbose logging
agent -tools semgrep -target . -verbose

# Check scanner output manually
semgrep --config auto .
```

---

## Next Steps

### Learn More

- **[Configuration Reference](./CONFIGURATION_REFERENCE.md)** - Full agent.yaml reference
- **[Agent README](../README.md)** - Complete documentation
- **[SDK Documentation](../../sdk/README.md)** - Build custom tools

### Advanced Topics

- **Retry Queue** - Network resilience for unreliable connections
- **Custom Scanners** - Integrate proprietary tools
- **Kubernetes Deployment** - Run agents in K8s clusters

---

## Need Help?

- 📚 **Documentation:** [docs.openctem.io](https://docs.openctem.io)
- 💬 **Discord:** [discord.gg/openctemio](https://discord.gg/openctemio)
- 🐛 **Issues:** [GitHub Issues](https://github.com/openctemio/agent/issues)

---

**Happy scanning! 🔍**
