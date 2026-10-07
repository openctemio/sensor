# Sensor Quick Start Guide

Get your first security scan running in **5 minutes**.

---

## What is the OpenCTEM sensor?

The OpenCTEM sensor (`openctemio-sensor`, formerly the OpenCTEM Agent) is a **command-line security scanner** that runs tools like Semgrep, Betterleaks, and Trivy, then pushes results to the OpenCTEM platform.

**Use Cases:**
- 🏃 **CI/CD Pipelines** - see [openctemio/ci](https://github.com/openctemio/ci)
- 🖥️ **Production Scanning** - Server-controlled daemon mode
- 🔄 **Scheduled Scans** - Periodic scanning of code repositories

---

## Installation

### Option 1: Binary (Recommended)

**Linux (amd64):**
```bash
curl -sSL https://github.com/openctemio/sensor/releases/latest/download/openctemio-sensor_linux_amd64.tar.gz | tar xz
sudo mv openctemio-sensor /usr/local/bin/
openctemio-sensor --version
```

**macOS (Apple Silicon):**
```bash
curl -sSL https://github.com/openctemio/sensor/releases/latest/download/openctemio-sensor_darwin_arm64.tar.gz | tar xz
sudo mv openctemio-sensor /usr/local/bin/
openctemio-sensor --version
```

### Option 2: Docker

```bash
docker pull ghcr.io/openctemio/sensor:latest
```

### Option 3: Go Install

```bash
go install github.com/openctemio/sensor@latest
```

---

## First Scan (5 Minutes)

### Step 1: Get API Key

1. Login to OpenCTEM UI at [http://localhost:3000](http://localhost:3000)
2. Navigate to **Settings → Sensors**
3. Click **"Create Sensor"**
4. Choose type: **Scanner**
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
openctemio-sensor -tools semgrep,betterleaks,trivy -target . -push -verbose
```

**What this does:**
- **semgrep** - Scans for code vulnerabilities (SAST)
- **betterleaks** - Detects exposed secrets
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

### Use Case 1: CI/CD Pipeline

Use [openctemio/ci](https://github.com/openctemio/ci) (GitHub Action,
reusable workflow, GitLab templates). It reports with the CI job's OIDC
identity: no API key in CI secrets.

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
  - name: betterleaks
    enabled: true

targets:
  - /path/to/project
```

> `-config` reads the keys of `Config` in `main.go`: `sensor:`, `server:`,
> `outbox:`, `retry_queue:` (deprecated), `scanners:`, `collectors:`,
> `targets:`. Files written for the agent release (`agent:` block,
> `server.agent_id`) still load, with a deprecation warning.

Run the daemon:

```bash
openctemio-sensor -daemon -config sensor.yaml
```

The sensor will:
1. Connect to the platform
2. Poll for scan commands from the server
3. Execute scans automatically
4. Send heartbeats
5. Keep every result in its outbox (`/var/lib/openctem/outbox`, else
   `~/.openctem/outbox`) until the platform accepted it, so an outage or a
   restart loses nothing (see the README, "Results delivery and the outbox")

---

### Use Case 3: Docker Sensor (scans dispatched by the platform)

The default image (`sensor:latest`, same as `latest-default`) runs the server-controlled daemon by default
(`-daemon -enable-commands -verbose`). It connects to the platform and runs
the scans the platform dispatches to it, with every scanner installed in the
image (semgrep, betterleaks, trivy, nuclei in the default image). It reports
them, with their versions, on its heartbeat, so the platform needs no tool
list. It needs the platform URL; without an API key it pairs on first start
(see "Pair the sensor" below):

```bash
docker run -d --name openctem-sensor --restart unless-stopped \
  -e API_URL=https://api.example.com \
  -e SENSOR_CA_FINGERPRINT=<from the install snippet, optional> \
  -e SENSOR_ALLOW_PRIVATE_TARGETS=1 \
  -v /srv/repos:/scan \
  -v openctem-outbox:/var/lib/openctem/outbox \
  -v openctem-state:/var/lib/openctem/state \
  -v openctem-content:/var/lib/openctem/content \
  ghcr.io/openctemio/sensor:latest
```

`openctem-state` keeps the sensor's paired identity and signing key (or, for a
legacy bearer key, the key it renews on its own; keep it with the container); `openctem-content` caches scanner content (trivy DB, nuclei
templates, semgrep rules), which can be deleted and is downloaded again.

The same with Docker Compose:

```yaml
services:
  sensor:
    image: ghcr.io/openctemio/sensor:latest
    restart: unless-stopped
    environment:
      API_URL: https://api.example.com
      # API_KEY: ${SENSOR_API_KEY}     # legacy bearer key; unset, the sensor pairs
      # SENSOR_PROTOCOL: auto          # auto | v2 (v1 is retired)
      # SENSOR_OUTBOX_MAX_BYTES: 1GiB
    volumes:
      - /srv/repos:/scan
      - outbox:/var/lib/openctem/outbox   # results not yet accepted by the platform
      - state:/var/lib/openctem/state     # the paired identity and key (keep it)
      - content:/var/lib/openctem/content # scanner content cache (disposable)
volumes:
  outbox:
  state:
  content:
```

- **Keep the outbox volume.** The sensor writes every result to
  `/var/lib/openctem/outbox` before sending it and deletes it only once the
  platform accepted it. Without a volume, results still queued when the
  container is re-created (platform down, image upgrade) are lost. Give each
  sensor its own volume; a second sensor on the same one refuses to start.

- Without `API_URL` the container exits with code 2 and names the missing
  variable. Without `API_KEY` it pairs (below).

### Pair the sensor (no key to copy)

A sensor started without `API_KEY` pairs with the platform on first start
(api RFC-052). It creates its own Ed25519 key, never sends it, and prints:

```
Pair this sensor in OpenCTEM: Sensors > Pair a sensor
  Code:        K7QM-4ZTD
  Fingerprint: 512 · tiger · violet · anchor    (expires 10:42)
```

An administrator enters the code under **Sensors > Pair a sensor**, checks
that the console shows the same fingerprint (and the host and source address
it expects), ticks "the fingerprint matches", re-authenticates and approves.
The sensor then signs every request with its key; nothing secret was ever
typed or pasted. With Docker, read the code with `docker logs openctem-sensor`.

- `openctemio-sensor pair` pairs and exits (for a host prepared before the
  daemon runs); `openctemio-sensor pair <CODE>` attaches to a code an
  administrator created with **Expect a sensor**, and prints the fingerprint
  to compare in the console.
- `openctemio-sensor pair -repair` replaces a lost or compromised key of a
  paired sensor; an administrator approves it again and the old key is
  revoked.
- The identity lives in `<state dir>/identity/` (`signing.key`,
  `identity.json`): 0600 files in a 0700 directory owned by the sensor's
  user. Looser permissions stop the sensor with the exact `chmod`/`chown` to
  run. Keep the state volume: losing it means pairing again.
- The install snippet may carry `SENSOR_CA_FINGERPRINT` (the SHA-256 of the
  platform CA the sensor must see in the TLS chain; nothing else is trusted
  for platform requests) and `SENSOR_PLATFORM_KEY` (the platform's pairing
  key). Both are public values that stop a fake platform at first contact.
  With `SENSOR_CA_FINGERPRINT`, `API_URL` must name the platform by the host
  name in its certificate, not by an IP address (`pair` refuses an IP URL;
  the daemon warns in its config report, `platform.ca_pin_host`).
- An approved sensor starts as **New**: passive work only, no credentials,
  until an administrator promotes it.
- The sensor detects its scanners at start-up ("Tools: semgrep, betterleaks,
  trivy, nuclei (detected ...)") and reports them on every heartbeat. The
  platform dispatches a scan only to sensors that report its tool installed.
- `SENSOR_TOOLS` (or `-tools`) is optional. It is an allowlist: only those
  scanners run and are reported. A listed scanner that is not installed is
  reported as not installed.
- `SENSOR_ALLOW_PRIVATE_TARGETS=1` is needed only to scan RFC1918 / ULA
  addresses. Only `1` (or `0`) is accepted; `true` stops the sensor at startup.
- Code scanners (betterleaks, semgrep, trivy fs) get a repository asset's name,
  resolved inside `SENSOR_SCAN_ROOTS` (default `/scan`, the working directory).
  Mount the repositories there.
- The sensor polls when the platform's heartbeat says there is work (the
  heartbeat doorbell), so a dispatched scan starts within one heartbeat, at
  most 30 s on an idle platform.
- **Images up to v0.3.0** default to `-platform -verbose`, the hosted-platform
  self-registration mode the open-source API does not serve, so the container
  exits with `failed to register sensor`. With those images pass the daemon
  flags yourself (`... sensor:v0.4.2 -daemon -enable-commands -tools
  nuclei,gitleaks,trivy`). They carry gitleaks rather than betterleaks, their semgrep does not start (missing
  `pkg_resources`), and gitleaks and semgrep write their report next to the
  scanned code, so mount the repositories **read-write** with them.

### Use Case 4: Docker One-Shot Scan

Arguments replace the default command, so the same image runs one scan and
exits:

```bash
docker run --rm \
  -v "$(pwd)":/scan \
  -e API_URL=https://api.openctem.io \
  -e API_KEY=your-api-key \
  ghcr.io/openctemio/sensor:latest \
  -tools semgrep,betterleaks,trivy -target /scan -push
```

---

## Connecting to the Platform

### Which URL

`API_URL` is the **API** base URL, the address whose `/health` answers
`{"status":"healthy"}`. It is not the web UI: the UI's `/api/v1` proxy does not
forward the sensor's key, and a current UI answers sensor requests with
`421 WRONG_ENDPOINT`.

The sensor reaches a platform on loopback, a private network, a Docker network
name (`http://api:8080`) or a Kubernetes service name without any extra
setting. Only cloud-metadata / link-local addresses are refused. The
`OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE` / `..._ALLOW_LOOPBACK` workarounds that
the agent release needed are no longer required; remove them, because they also
widen what scan targets may reach.

A plain `http://` URL to anything but loopback works but prints once:
`API base URL http://... uses plain http: the API key is sent in clear text`.
Use `https://` outside a private network.

### HTTPS with a private CA

The images are Debian-based (`python:3.12-slim`, `debian:bookworm-slim`) and
run as the non-root user `openctem` (uid 1001 in the CI images), so `update-ca-certificates` cannot run inside them. Any of these
make the sensor trust your CA:

| Method | Example |
|---|---|
| Mount the CA into `/etc/ssl/certs` (recommended) | `-v /path/ca.pem:/etc/ssl/certs/my-ca.pem:ro` |
| `SSL_CERT_DIR` | `-v /path/ca.pem:/certs/my-ca.pem:ro -e SSL_CERT_DIR=/certs` |
| `SSL_CERT_FILE` | `-v /path/ca.pem:/certs/my-ca.pem:ro -e SSL_CERT_FILE=/certs/my-ca.pem` |

The public CAs keep working with each of these. Mounting into
`/usr/local/share/ca-certificates/` does **not** work (it needs
`update-ca-certificates`). Without the CA the sensor logs
`tls: failed to verify certificate: x509: certificate signed by unknown authority`
and keeps retrying. In Kubernetes, mount the CA from a ConfigMap at
`/etc/ssl/certs/<name>.pem` with `subPath`.

### Through an HTTP proxy

A sensor has three kinds of outbound traffic, and each has its own setting
(api RFC-034):

| Traffic | Setting | When unset |
|---|---|---|
| To the platform | `SENSOR_CONTROL_PROXY` (a proxy URL, or `direct`) | `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` |
| Content and feeds (nuclei templates, semgrep rules, trivy's database, KEV/EPSS) | `SENSOR_CONTENT_PROXY` (a URL, or `direct`) | the platform setting |
| Scanners to their targets | `SENSOR_SCAN_PROXY`: `inherit` or `direct` | `inherit` |

- **Proxy URLs.** They may be `http://`, `https://`, `socks5://` or
  `socks5h://`, with `user:password@` when the proxy needs Basic or SOCKS5
  authentication. `NO_PROXY` is the bypass list for all of them.
- **HTTP proxies use `CONNECT`.** A platform reached at an `https://` URL
  goes through the proxy as a `CONNECT` tunnel, so TLS stays end to end.
- **The usual corporate setup** sends everything outbound through one
  proxy:

  ```bash
  -e HTTPS_PROXY=http://proxy.corp:3128 -e NO_PROXY=api.internal,.svc
  ```

- **Scanners.** By default (`inherit`), scanner processes get the same
  `HTTP(S)_PROXY` and `NO_PROXY`, and the sensor prints a warning at start.
  Their traffic to targets then goes through the proxy unless `NO_PROXY`
  lists the target, which is rarely what you want for internal targets.
  - Set `-e SENSOR_SCAN_PROXY=direct` so that scanners connect directly.
    Content downloads keep using the proxy.
  - Or set `SENSOR_SCAN_PROXY=inherit` to keep the inheritance on purpose
    (the warning stops).
- **Content checks.** Content downloads check the target address **before**
  they use the proxy, so the proxy cannot be used to reach private or
  cloud-metadata addresses. On a network without public DNS, the default
  content hosts (GitHub, semgrep.dev, the KEV and EPSS feeds) are resolved by
  the proxy.
- **TLS-inspecting proxies.** Mount the proxy's CA and set
  `SENSOR_CA_CERT_FILE` (above). It is trusted for the platform and for
  content downloads. Scanner processes read `SSL_CERT_FILE`.

---

## Available Scanners

| Tool | Type | Description |
|------|------|-------------|
| `semgrep` | SAST | Code analysis with taint tracking |
| `betterleaks` | Secret | Secret and credential detection |
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
| `SENSOR_TOOLS` | No | Optional allowlist of scanners, used when `-tool`/`-tools` is not given; without it a server-controlled daemon runs every installed native scanner |
| `SENSOR_MAX_JOBS` | No | Cap on commands the sensor runs at once, 1-100 (or `-max-concurrent`). Unset: the sensor sizes it from its CPU, memory and tool costs |
| `SENSOR_STATE_DIR` | No | Where the sensor keeps local state (tool cost history); default the outbox's parent directory |
| `REGION` | No | Deployment region (e.g., `us-east-1`) |
| `SENSOR_ALLOW_PRIVATE_TARGETS` | No | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. Default off. IMDS / loopback / CGNAT stay blocked regardless. See [security hardening guide](../../docs/operations/security-hardening.md#agent-private-target-opt-in). |

*Required when using `-push` flag or daemon mode. A server-controlled daemon
(`-daemon -enable-commands`, the `-default` image's default) refuses to start
without them.

> **On-prem scanning:** if your sensor runs inside a corporate network and scans services on `10.x` / `192.168.x` / `172.16-31.x`, set `SENSOR_ALLOW_PRIVATE_TARGETS=1` (`AGENT_ALLOW_PRIVATE_TARGETS=1` still works). Without it, the sensor refuses private-IP targets to prevent SSRF.

### Command-Line Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-tool` | Single scanner | `-tool semgrep` |
| `-tools` | Multiple scanners | `-tools semgrep,betterleaks,trivy` |
| `-target` | Scan target path | `-target /path/to/code` |
| `-push` | Push results to platform | `-push` |
| `-verbose` | Detailed logs | `-verbose` |
| `-daemon` | Run as daemon | `-daemon` |
| `-config` | Config file path | `-config sensor.yaml` |

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
4. A key stops working when the sensor is revoked or deleted, or its key is
   regenerated (*Settings → Sensors*). Regenerate the key and update `API_KEY`.
   With key auto-renewal the current key is in `sensor-credentials.json` in
   the state directory (`/var/lib/openctem/state`), not in `API_KEY`. A
   container recreated without that volume starts with the retired
   `API_KEY`: keep the volume, or regenerate the key.
5. A running sensor that is **deactivated** is not rejected: it keeps
   heartbeating, logs `paused by platform`, takes no jobs, and resumes when
   reactivated. In v0.3.0 a sensor *started* while deactivated exits with
   `Invalid API key`; reactivate it before restarting.

---

### Other connection messages

| Message | Cause | Fix |
|---|---|---|
| `x509: certificate signed by unknown authority` | The API uses a private CA | [Trust the CA](#https-with-a-private-ca) |
| `http 421 ... WRONG_ENDPOINT` or `API key required` | `API_URL` points at the web UI or at a proxy that strips `Authorization` | Point `API_URL` at the API |
| `ssrf guard: blocked IP ...` | An agent release (v0.2.x, sdk-go < v0.7.2) refusing a private or loopback platform | Upgrade to sensor v0.3.0 |
| `failed to register sensor: ... bootstrap token`, or `-platform mode has been removed` | An image up to v0.3.0 (default `-platform`), or a command line that still passes `-platform`; the mode is gone | [Run the daemon flags](#use-case-4-docker-daemon-scans-dispatched-by-the-platform) |
| `SENSOR_ALLOW_PRIVATE_TARGETS="true" is not recognized` | Only `1` or `0` is accepted | Set `1` |
| `Report path is not writable: /scan/...` (betterleaks) | The repository is mounted read-only (sensor v0.3.0) | Mount it read-write |

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
- 🐛 **Issues:** [GitHub Issues](https://github.com/openctemio/sensor/issues)

---

**Happy scanning! 🔍**
