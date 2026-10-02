# OpenCTEM Sensor

Open-source security scanning sensor for Continuous Threat Exposure Management (CTEM).
Formerly the *OpenCTEM Agent*: see [Upgrading from the agent release](#upgrading-from-the-agent-release).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://golang.org/)

## Overview

The OpenCTEM sensor (`openctemio-sensor`) is a lightweight, extensible security scanning sensor that integrates with the OpenCTEM platform. It supports multiple scanning tools and can run in various modes.

## Features

- **Multi-tool Support**: Semgrep, Trivy, Nuclei, Betterleaks, and more
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
| Betterleaks | Secrets | Secret detection |
| Naabu | Recon | Port scanning |
| Subfinder | Recon | Subdomain enumeration |
| HTTPx | Recon | HTTP probing |
| DNSx | Recon | DNS enumeration |
| Katana | Recon | Web crawling |

## Quick Start

### Installation

```bash
# From source
git clone https://github.com/openctemio/sensor.git
cd agent
go build -o openctemio-sensor .

# Or download a release archive
curl -sSL https://github.com/openctemio/sensor/releases/download/<version>/openctemio-sensor_<version>_linux_amd64.tar.gz | tar xz
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
./openctemio-sensor -tool betterleaks -target ./ -output results.sarif
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

Images are published as `ghcr.io/openctemio/sensor:<version>-<variant>`
(and `latest-<variant>`). The `default` variant is also the plain tag:
`sensor:<version>` and `sensor:latest` (from v0.4.2; `-default` still works).

| Variant | Tools | Default command |
|---|---|---|
| `default` | semgrep, betterleaks, trivy, nuclei | `-daemon -enable-commands -verbose` (server-controlled sensor; tools from `SENSOR_TOOLS`) |
| `ci` | semgrep, betterleaks, trivy | `--help` (pass a one-shot command) |
| `semgrep`, `betterleaks`, `trivy`, `nuclei` | that tool | `-tool <tool> --help` |

```bash
# Long-running sensor the platform dispatches scans to
docker run -d -e API_URL=https://<platform> -e API_KEY=<sensor key> \
  -v /srv/repos:/scan -v openctem-outbox:/var/lib/openctem/outbox \
  ghcr.io/openctemio/sensor:latest

# One scan: arguments replace the default command
docker run --rm -v "$(pwd)":/scan ghcr.io/openctemio/sensor:latest \
  -tool semgrep -target /scan

# Build locally
docker build -t openctemio/sensor .
```

A server-controlled daemon without `API_URL` or `API_KEY` exits with code 2
and names what is missing. Every image is smoke-tested before it is published
(`scripts/image-smoke-test.sh`): each bundled tool must run and
`openctemio-sensor -list-tools` must report it `available`.

## CI/CD Integration

### GitHub Actions
```yaml
- uses: openctemio/sensor/ci/github@main
  with:
    tool: semgrep
    target: ./src
    api-url: ${{ secrets.OPENCTEM_API_URL }}
    api-key: ${{ secrets.OPENCTEM_API_KEY }}
```

### GitLab CI
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/openctemio/sensor/main/ci/gitlab/semgrep.yml'
```

See [ci/](ci/) for more examples.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_URL` | Backend API base URL (or `-api-url` flag) | - |
| `API_KEY` | API authentication key (or `-api-key` flag) | - |
| `SENSOR_ID` | Sensor identifier (or `-sensor-id` flag) | auto |
| `SENSOR_TOOLS` | Comma-separated scanners when `-tool`/`-tools` is not given | - (`semgrep,betterleaks,trivy,nuclei` in the `-default` image) |
| `SENSOR_NAME` | Platform-mode sensor name (or `-name` flag) | auto |
| `REGION` | Deployment region (or `-region` flag) | `default` |
| `SENSOR_ALLOW_PRIVATE_TARGETS` | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. IMDS / loopback / CGNAT stay blocked regardless. See [Scanner safety model](#scanner-safety-model). | off |
| `SENSOR_SCAN_ROOTS` | Directories (`:`-separated) that filesystem targets of dispatched code scans (betterleaks, semgrep, trivy fs) must resolve inside; a relative target is taken relative to the first. See [Scanner safety model](#scanner-safety-model). | the sensor's working directory (`/scan` in the images) |

`API_URL`, `API_KEY` and `BOOTSTRAP_TOKEN` keep their names. The pre-rename
names `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` and `-agent-id`
still work (see [Upgrading](#upgrading-from-the-agent-release)).

### Config File (sensor.yaml)

`-config` reads the keys of `Config` in `main.go`: `sensor:`, `server:`,
`outbox:`, `retry_queue:` (deprecated), `scanners:`, `collectors:` and
`targets:`.

```yaml
sensor:
  name: production-scanner
  region: default
  heartbeat_interval: 1m
  enable_commands: true
  command_poll_interval: 30s   # used only with an API without the heartbeat doorbell
  # disable_doorbell: true     # poll every command_poll_interval regardless

server:
  base_url: https://api.openctem.io
  api_key: ${API_KEY}
  sensor_id: your-sensor-id
  timeout: 30s
  protocol: auto               # auto | v1 | v2 (SENSOR_PROTOCOL)

outbox:                        # undelivered results; on by default with -daemon
  dir: /var/lib/openctem/outbox
  max_bytes: 1GiB
  max_age: 168h

scanners:
  - name: semgrep
    enabled: true
  - name: betterleaks
    enabled: true

targets:
  - /path/to/project
```

### Heartbeat doorbell

With an API that supports it (RFC-023 §9.2a) the daemon's heartbeat answer
says when there is work, and the daemon polls only then:

| Heartbeat answer | Sensor |
|---|---|
| `pending_jobs > 0` | polls for commands immediately |
| `next_heartbeat_seconds` | next heartbeat after that long (5 s – 5 min) |
| hints present | no fixed 30 s poll; a safety poll every 5 min |
| no hints (older API) | polls every `command_poll_interval`, as before |
| `pause` (sensor disabled) | takes no new jobs, running jobs finish, keeps heartbeating; logs `paused by platform`; resumes on the first heartbeat without `pause` |
| `drain` | like `pause`, until restart |
| `rotate_key` | renews the key now (with `-key-autorenew`), saving it to `-credentials` |
| `update`, unknown | logged only |

### Results delivery and the outbox

**Protocol.** Results go over protocol v2 (`PUT /api/v2/sensor/results/{id}`,
api RFC-026) when the platform offers it, and over v1 otherwise:
`SENSOR_PROTOCOL` / `-protocol` / `server.protocol` is `auto` (default), `v1`
or `v2` (`v2` fails against a platform without it). In `auto` the sensor asks
on its heartbeat, so an older platform keeps working unchanged.

**Outbox.** A daemon writes every result to its outbox **before** sending it
and deletes it only once the platform accepted it, so a crash, `kill -9`, an
API outage or a restart loses nothing; the backlog is sent, oldest first, as
soon as a heartbeat gets through. A command is reported complete only after
its results were accepted. Results the platform refuses for good (malformed,
tool not declared, ...) move to `dead/` with the reason instead of being
retried forever. The outbox never fills the disk: past the size or age cap the
oldest entries are dropped with a warning in the log, a metric and on the
heartbeat (the API stores it with the sensor).

| Setting | Default | |
|---|---|---|
| `SENSOR_OUTBOX` (`outbox.enabled`) | `on` for `-daemon`, `off` for one-shot runs | `on` keeps a one-shot run's results for its next run |
| `SENSOR_OUTBOX_DIR` / `-outbox-dir` (`outbox.dir`) | `/var/lib/openctem/outbox`, else `~/.openctem/outbox` | **mount a persistent volume here** |
| `SENSOR_OUTBOX_MAX_BYTES` (`outbox.max_bytes`) | `1GiB` (and at most half of the free space) | e.g. `512MiB` |
| `SENSOR_OUTBOX_MAX_AGE` (`outbox.max_age`) | `168h` | |
| `SENSOR_OUTBOX_KEY_FILE` (`outbox.key_file`) | `<dir>/outbox.key` | the AES-256-GCM key, created on first start; point it at a mounted secret to keep it off the data volume |

Files are 0600 in a 0700 directory and encrypted; one sensor process per
directory (a second one refuses to start). While the sensor runs, its
heartbeat reports the outbox state to the platform (pending results, oldest
age, dead letters, evictions). With the sensor stopped:

```bash
openctemio-sensor -outbox-status            # pending, dead letters with reasons
openctemio-sensor -outbox-requeue-dead      # after fixing the cause; the next start delivers them
# in Docker, against the same volume:
docker run --rm -v openctem-outbox:/var/lib/openctem/outbox ghcr.io/openctemio/sensor:latest -outbox-status
```

Upgrading: the old `-retry-queue` / `RETRY_QUEUE=true` now turns the outbox on
(also for one-shot runs), and results an older sensor left in its retry-queue
directory (`RETRY_DIR`, default `~/.openctem/retry-queue`) are imported once.

### Rejected key and connection failures

The daemon checks its key with its first heartbeat. When the platform rejects
it (HTTP 401/403: the key is wrong, revoked, expired or regenerated, or the
sensor was deleted), the daemon **stays up**: it stops polling for jobs and
checks again after 30 s, doubling to at most 10 min. It logs one line per
attempt, without `-verbose`:

```
[connection] the platform rejected the API key (HTTP 401, key rda_5d22…): ... Create or regenerate a key under Settings → Sensors, set API_KEY to it and restart the sensor. Not polling for jobs; next check in 30s (attempt 1)
```

It carries on by itself once the key is accepted again, for example after
the sensor is re-activated. A 401 `API key required` means the key never
reached the API: `API_URL` points at the web UI or at a proxy that strips
the `Authorization` header. Network failures are logged at 1, 2, 4, 8, ...
consecutive attempts, along with the recovery.

A one-shot run (`-push` without `-daemon`, e.g. in CI) exits with code
**78** (`EX_CONFIG`) when its key is rejected, so the job fails with that
message rather than a generic error.

Restart policy: the daemon no longer exits on a rejected key, so
`restart: unless-stopped` / Kubernetes `restartPolicy: Always` cannot turn
it into a restart loop. Don't treat exit code 78 as transient in wrappers
that retry one-shot runs.

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

Targets are checked according to the scanner that receives them. Network
scanners (nuclei, the recon tools, and any scanner the sensor does not know)
get the SSRF guard above. Code scanners (betterleaks, semgrep, trivy fs/config)
take a directory: it must resolve, symlinks followed, inside the scan
workspace (`SENSOR_SCAN_ROOTS`, default the working directory), and never a
sensitive host path (`/etc`, `~/.ssh`, ...). A remote repository URL given to a
code scanner is SSRF-guarded like any network target.

A daemon with `-enable-commands` scans only what the server dispatches. It
runs scheduled scans of its own only for targets you configure explicitly
(`-target`, or `targets:` in the config file).

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

## Upgrading: gitleaks → Betterleaks

[Betterleaks](https://github.com/betterleaks/betterleaks) replaces gitleaks as
the secret scanner. It is gitleaks' successor by its original author (MIT): v1
keeps gitleaks' CLI flags, config format and JSON report, and adds BPE-token
filtering, Expr rule filters and validation, recursive decoding and scanning
inside archives (on by default).

- The image is `ghcr.io/openctemio/sensor:<version>-betterleaks`. No
  `-gitleaks` image is published from this release on; existing `-gitleaks`
  tags stay pullable and frozen.
- The scanner is `betterleaks` (`-tool betterleaks`, `SENSOR_TOOLS`,
  `scanners: - name: betterleaks`). `gitleaks` in an existing command line,
  config or CI template still works: it runs betterleaks and prints a note.
  A platform that has not migrated its scan configs and still dispatches
  `gitleaks` scans is handled the same way.
- `.gitleaks.toml` custom rules keep working (betterleaks reads them;
  `.betterleaks.toml` is the new name).
- Findings keep their identity: a secret both tools report has the same
  fingerprint, so existing findings are updated, not duplicated. Rule sets
  differ, for example betterleaks reports an AWS access key ID only together
  with its secret key, so a few gitleaks-only findings are auto-resolved by
  the first full betterleaks scan, and archives produce new ones.
- Upgrade every sensor that scans a repository together: a gitleaks sensor
  and a betterleaks sensor on the same repository resolve and reopen each
  other's rule-set differences.
- The platform maps reports from older sensors (`tool: gitleaks`) to
  `betterleaks` at ingest and migrates scan configs and existing findings
  (API migration 000241).

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
