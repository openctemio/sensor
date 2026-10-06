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
| `default` | semgrep, betterleaks, trivy, nuclei | `-daemon -enable-commands -verbose` (server-controlled sensor; runs and reports every installed tool, `SENSOR_TOOLS` optionally narrows them) |
| `ci` | semgrep, betterleaks, trivy | `--help` (pass a one-shot command) |
| `semgrep`, `betterleaks`, `trivy`, `nuclei` | that tool | `-tool <tool> --help` |

```bash
# Long-running sensor the platform dispatches scans to
docker run -d -e API_URL=https://<platform> \
  -v /srv/repos:/scan -v openctem-outbox:/var/lib/openctem/outbox \
  -v openctem-state:/var/lib/openctem/state -v openctem-content:/var/lib/openctem/content \
  ghcr.io/openctemio/sensor:latest

# One scan: arguments replace the default command
docker run --rm -v "$(pwd)":/scan ghcr.io/openctemio/sensor:latest \
  -tool semgrep -target /scan

# Build locally
docker build -t openctemio/sensor .
```

A server-controlled daemon without `API_URL` exits with code 2. Without
`API_KEY` it pairs on first start: it prints a code and a fingerprint for an
administrator to approve under Sensors > Pair a sensor, then signs every
request with its own key (`openctemio-sensor pair` does the same and exits;
see docs/QUICK_START.md). Every image is smoke-tested before it is published
(`scripts/image-smoke-test.sh`): each bundled tool must run and
`openctemio-sensor -list-tools` must report it `available`.

#### Verifying images and releases

Release images are signed by digest with [cosign](https://docs.sigstore.dev/)
keyless signing: the signature's certificate names this repository's
`docker-publish.yml` workflow at the release tag, issued from GitHub's OIDC
token. No long-lived signing key exists. Check an image before you run it:

```bash
cosign verify ghcr.io/openctemio/sensor:v0.6.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml@refs/tags/v0.6.0
```

Release archives: `checksums.txt` is signed the same way by `release.yml`
(`checksums.txt.sigstore.json`):

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/openctemio/sensor/.github/workflows/release.yml@refs/tags/v0.6.0
sha256sum -c checksums.txt --ignore-missing
```

Images and archives published before signing was added carry no signature.

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
| `SENSOR_TOOLS` | Optional allowlist: comma-separated scanners when `-tool`/`-tools` is not given. A server-controlled daemon without one runs every installed native scanner (semgrep, betterleaks, trivy, nuclei) and reports them to the platform | - (every installed tool) |
| `SENSOR_NAME` | Platform-mode sensor name (or `-name` flag) | auto |
| `SENSOR_MAX_JOBS` | Cap on commands run at once, 1-100 (or `-max-concurrent`, `sensor.max_jobs`); the live count follows CPU, memory and tool costs | no cap |
| `SENSOR_DRAIN_GRACE` | On SIGTERM, how long running scans may finish before they are stopped and handed back to the platform (allow it plus ~15 s in `stop_grace_period` / `terminationGracePeriodSeconds`) | `30s` |
| `SENSOR_STATE_DIR` | Local state: the renewed API key (`sensor-credentials.json`, see "API key renewal") and the tool cost history (`tool-costs.json`) | `/var/lib/openctem/state` when writable, else `~/.openctem` |
| `REGION` | Deployment region (or `-region` flag) | `default` |
| `SENSOR_ALLOW_PRIVATE_TARGETS` | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. IMDS / loopback / CGNAT stay blocked regardless. See [Scanner safety model](#scanner-safety-model). | off |
| `SENSOR_SCAN_ROOTS` | Directories (`:`-separated) that filesystem targets of dispatched code scans (betterleaks, semgrep, trivy fs) must resolve inside; a relative target is taken relative to the first. See [Scanner safety model](#scanner-safety-model). | the sensor's working directory (`/scan` in the images) |
| `SENSOR_TEMPLATE_SIGNING_KEYS` | The platform's template-signing public keys for this sensor's tenant (base64 Ed25519, comma-separated; from `GET /api/v1/scanner-templates/signing-key`). Custom templates in a scan run only with a signature one of them verifies. See [Nuclei template trust](#nuclei-template-trust-and-rate-limits). | none: scans with custom templates fail |
| `SENSOR_LOCAL_POLICY` | The sensor-local policy file (or `-local-policy`): targets, ports, tools, job types, custom templates, interactsh, rate and a kill switch, set by the network owner; jobs outside it are refused whatever the platform sends. A policy that cannot be loaded stops the sensor. See [Sensor-local policy](#sensor-local-policy). | `/etc/openctem/sensor-policy.yaml` when it exists, else none |
| `SENSOR_TENABLE_SC_CONFIG` | The Tenable.sc connector config (or `-tenable-sc-config`): instances, key files, CA or pins and the operations and repositories the platform may use. A config that cannot be loaded stops the sensor. See [Tenable.sc connector](#tenablesc-connector). | `/etc/openctem/connectors/tenable-sc.yaml` when it exists, else the `TENABLE_SC_*` shorthand, else off |
| `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` | Shorthand policy without a file: `targets.allow` (comma-separated CIDRs, IPs, names, `*.domain`) and `ports.allow` (`80,443,8000-8999`) | - |
| `SENSOR_KILL_SWITCH_FILE` | While this file exists the sensor runs no job and heartbeats "paused by local policy" (also `kill_switch_file` in the policy) | - |
| `SENSOR_DNS_RESOLVERS` | DNS resolvers dnsx, naabu and subfinder use (comma-separated IP or IP:port). Unset: the nameservers in `/etc/resolv.conf`, as httpx, katana and nuclei use. The tools' built-in public resolver lists are never used, so enumerated names do not go to third-party resolvers and internal or split-horizon names resolve. An invalid value fails recon jobs | `/etc/resolv.conf` |
| `SENSOR_SANDBOX` | How every tool run is confined (see [Tool sandbox](#tool-sandbox)): `auto` enforces what the host supports and logs the rest, `required` refuses to start unless every control is enforced, `off` runs tools as plain child processes. One-shot runs sandbox only when this is set | `auto` (daemon), `off` (one-shot) |
| `SENSOR_NUCLEI_MAX_RATE_LIMIT` | Ceiling on nuclei requests per second (`-rate-limit`). A scan may ask for less, never more | `150` |
| `SENSOR_NUCLEI_MAX_CONCURRENCY` | Ceiling on nuclei templates in parallel (`-c`) | `25` |
| `SENSOR_NUCLEI_MAX_BULK_SIZE` | Ceiling on nuclei hosts in parallel per template (`-bs`) | `25` |

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
  # max_jobs: 8                # cap on commands run at once, 1-100 (SENSOR_MAX_JOBS); unset: follow CPU/memory

server:
  base_url: https://api.openctem.io
  api_key: ${API_KEY}
  sensor_id: your-sensor-id
  timeout: 30s
  protocol: auto               # auto | v2, the same (SENSOR_PROTOCOL; v1 is refused)

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
| `rotate_key` | renews the key now (when key auto-renewal is on, see "API key renewal"), saving it to the credentials file |
| `update`, unknown | logged only |

### API key renewal

The daemon keeps its state in `SENSOR_STATE_DIR` (default
`/var/lib/openctem/state` when writable, else `~/.openctem`). A key it
renews is saved there (`sensor-credentials.json`, 0600, written atomically)
and used on the next start instead of `API_KEY`, because the renewal retires
the key the sensor was installed with. If `API_KEY` is changed to a key an
administrator regenerated, the new `API_KEY` wins. A file an earlier version
kept in `~/.openctem` is moved into the state directory.

Auto-renewal (`PLATFORM_KEY_AUTORENEW`, `-key-autorenew`): `true` / `false`
force it; unset, it is **on when the state directory survives the container
being recreated** (outside a container always; inside one, only on a mounted
volume that is not a tmpfs) and off otherwise, with the reason in the start-up
log. **Mount a volume at `/var/lib/openctem/state`** (the platform's install
snippets do). The images create the directory but do not declare it a
`VOLUME`: an anonymous volume is lost with the container. The platform
issues expiring keys only when its `SENSOR_KEY_TTL` is set; with no TTL a
renewal (once, on the first start with renewal on) yields a key that never
expires and nothing else happens.

### Tool sandbox

Every scanner run by the daemon is confined before it starts (sdk-go
`pkg/sensorkit/executor`, the `process` backend). The sensor binary re-executes itself
as a launcher, confines that process, then replaces it with the tool:

- a private, throwaway directory (its HOME and TMPDIR), removed after the run;
- resource limits: memory, processes and threads (a fork bomb stops at its
  allowance), file size, open files, no core dumps;
- no privilege escalation (no_new_privs);
- **Landlock**: the tool writes only in its directory and the paths its
  wrapper declares (a report directory, nuclei's private configuration), and
  cannot read the sensor's credentials file, outbox and its key, local policy,
  `-config` file or the Tenable.sc connector configuration;
- **seccomp**: ptrace, mount and namespaces, kernel modules, keyrings, bpf,
  perf and similar syscalls are refused;
- the sensor itself is non-dumpable, so a tool cannot read its memory or
  environment through `/proc`.

It needs no extra privileges and works under Docker's default seccomp profile
(Landlock needs Linux 5.13 or newer). At start the daemon logs `Tool sandbox:
auto; private task directory, rlimits, no_new_privs, landlock vN, seccomp true`
or a warning naming what the host does not support. Set
`SENSOR_SANDBOX=required` to refuse to start without all of it. The sensor
never uses a Docker socket.

### Results delivery and the outbox

**Protocol.** The sensor speaks protocol v2 (`/api/v2/sensor/*`, api RFC-026
and RFC-029) for everything: heartbeat, commands, suppressions, fingerprint
queries, key renewal and results. The platform retired protocol v1
(`/api/v1/agent/*`) in 2026-10, so the sensor needs an OpenCTEM API from
2026-10-02 on; against an older one every call fails with "the platform does
not serve sensor protocol v2". `SENSOR_PROTOCOL` / `-protocol` /
`server.protocol` is `auto` (default) or `v2`, which are the same; `v1` is
refused at start-up. The sensor is identified by its key alone.

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
directory (a second one refuses to start). Scanners cannot read the outbox or
its key (tool sandbox). Each report carries a stable id the platform uses as
its idempotency key, so a backlog sent after an outage, or a send whose answer
was lost, is stored exactly once. While the sensor runs, its
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

## Setup & health (config report)

On start the daemon runs read-only preflight checks and, when the platform
supports it, sends the results to the platform: open the sensor under
Settings → Sensors to see its **Setup & health** checklist, each problem
with why it matters and the exact fix (environment variable, Compose or Helm
snippet). The same problems are printed at start (`Warning: ...`) and a
summary line says `Preflight: N passed, M warning(s), K failed`.

What is checked: each tool's binary (missing or installed but failing to
run), whether the state directory survives a recreate, key renewal, the
scanner proxy, OOM protection, the trust store files (`SSL_CERT_FILE`,
`SSL_CERT_DIR`), the local policy and its template keys, unknown or legacy
setting names, unknown keys and unset `${VAR}`s in the `-config` file, and
`-daemon` without `-enable-commands`.

What is sent: check ids, codes and typed parameters (a path, a tool or a
setting name), and for every declared setting only whether it is set, where
it came from and whether its value is valid. **Setting values, secrets and
target ranges never leave the host.** Free text is scrubbed of secret values
and URL credentials before it is sent. Nothing the platform sends chooses
what is checked, and no check opens a connection.

## Scanner content updates

A scanner binary is pinned and checksum-verified in the image; the **content**
it scans with changes daily. In daemon mode the sensor manages that content
itself, so scans use a known, verified version instead of whatever a tool
fetches mid-scan:

| Content | Tool | Default source | Verification | Managed |
|---|---|---|---|---|
| `trivy-db` | trivy | `mirror.gcr.io/aquasec/trivy-db:2`, then `ghcr.io/aquasecurity/trivy-db:2` | manifest digest resolved first and downloaded by digest (trivy verifies every blob); `trivy version` must read schema 2; never older than the installed DB unless pinned | always |
| `trivy-java-db` | trivy | trivy's default | trivy reads its metadata | `SENSOR_CONTENT_TRIVY_JAVA_DB=true` (about 800 MB more) |
| `nuclei-templates` | nuclei | the release baked into the image, then the GitHub release (`releases/latest`) | archive sha256 against the release's `_checksums.txt`; safe extraction; at least 1000 templates that nuclei loads; `nuclei -validate` passes for all but `SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS` templates; scans run with `-disable-unsigned-templates` (signature check) and `-disable-update-check` | always |
| `semgrep-rules` | semgrep | `https://semgrep.dev/c/<ruleset>` | YAML check (rules with ids) and semgrep loads the bundle | only when rulesets are chosen (platform policy or `SENSOR_CONTENT_SEMGREP_RULESETS`) or a local rules path is set; otherwise semgrep keeps `--config auto` and the sensor reports that as unmanaged |

How it works: every refresh downloads into a staging directory, verifies,
and only then switches the `current` link atomically. A failed download or
check keeps the current version and is reported. A running scan keeps the
version it started with; the previous version is kept for rollback. Checks
run every 6 hours (±10% jitter, hourly while content is missing, stale or
failing) and on demand when the platform sends a `refresh_content` command
("Refresh content" on the Sensors page). The heartbeat reports each tool's
content (`tools[].content`: version, build time, source, digest, last error)
and each result carries the content its scan used (`tool.properties.content`).

The platform's content policy can set the refresh interval, a maximum age,
a pinned version (a trivy DB digest, a nuclei-templates tag) and semgrep
rulesets. **It can never choose where content comes from**: sources are only
this host's settings below.

| Variable | Default | |
|---|---|---|
| `SENSOR_CONTENT` | `on` | `off`: tools fetch their own content, as before |
| `SENSOR_CONTENT_DIR` | `$HOME/.openctem/content` (`/var/lib/openctem/content` in the images) | mount a volume here |
| `SENSOR_CONTENT_REFRESH_INTERVAL` | `6h` | 10m..720h; the policy may override |
| `SENSOR_CONTENT_KEEP` | `1` | previous versions kept for rollback (0..10) |
| `SENSOR_CONTENT_TRIVY_DB_REPOSITORY` | see above | comma list, tried in order; registry credentials from `TRIVY_USERNAME`/`TRIVY_PASSWORD` |
| `SENSOR_CONTENT_TRIVY_JAVA_DB` / `_REPOSITORY` | off / trivy default | |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_URL` | GitHub archive | `{version}` / `{bare_version}` placeholders; `https://` or a local file |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_CHECKSUMS_URL` | GitHub release asset | required with a mirror unless `_SHA256` is set |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_LATEST_URL` | GitHub API (only with the default archive URL) | GitHub-shaped JSON or a plain-text tag |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION` / `_SHA256` | none | pin a release / its archive digest |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_DIR` | none | a local template directory, installed as is |
| `SENSOR_CONTENT_NUCLEI_MIN_TEMPLATES` | `1000` | |
| `SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS` | `10` | templates of a release that may fail `nuclei -validate` before the release is refused; `0`: none |
| `SENSOR_CONTENT_SEMGREP_RULESETS` | none | e.g. `p/default,p/secrets` |
| `SENSOR_CONTENT_SEMGREP_REGISTRY_URL` | `https://semgrep.dev` | a registry mirror |
| `SENSOR_CONTENT_SEMGREP_RULES_PATH` | none | a local rules file or directory |
| `SENSOR_CONTENT_SEMGREP_SKIP_CHECK` | off | skip the semgrep load check (~1 min for `p/default`) |

**nuclei templates in detail:**

- The images (`default`, `full`, `nuclei`) bake one nuclei-templates release,
  pinned in the Dockerfiles with its archive SHA-256
  (`NUCLEI_TEMPLATES_VERSION` / `NUCLEI_TEMPLATES_SHA256`) and gated at build
  by `scripts/nuclei-templates-bake.sh`: any template that fails
  `nuclei -validate` with the pinned nuclei and is not in
  `docker/nuclei-templates-allowlist.txt` fails the build, and so does a
  scan run that logs an error or a release whose `.nuclei-ignore` stops
  excluding `dos`, `local`, `fuzz`, `bruteforce` or `txt-service`. The sensor
  adopts the baked set as its first managed version, with its release and
  archive digest, so a fresh sensor scans without downloading anything.
- Each nuclei run over a managed set gets its own nuclei configuration
  directory (`XDG_CONFIG_HOME`, removed after the run) naming that set and
  its release. nuclei confines helper files (payload wordlists, workflow
  subtemplates) to its configured templates directory: without this, every
  template that loads one failed with "access to helper file ... denied"
  (262 templates of v10.4.9, reported as "templates with runtime error").
  The run's `.nuclei-ignore` is the release's own exclusion list plus the
  baseline tags above.
- Template classes the sensor does not enable for its own set (`code`,
  `headless` unless configured, `file`, self-contained) are skipped by
  nuclei, not errors.
- Every finding carries `template_digest` (`sha256:` of the template file
  that matched) and `template_path`; every result carries the release
  (`tool.properties.content`: version and archive digest). A nuclei
  re-verification reports `template_digest`, `templates_version` and
  `templates_digest` in its evidence. The platform compares them to decide
  whether a re-check ran the same template content.

`openctemio-sensor -content-status` prints what is installed;
`-content-refresh` (with `-content-force` to re-download) refreshes now, for
example from cron on a host that runs one-shot scans (one-shot runs use
installed content but never download it).

**Air-gapped hosts:**

- trivy DB: copy the artifact into an internal registry
  (`oras copy mirror.gcr.io/aquasec/trivy-db:2 harbor.internal/aquasec/trivy-db:2`)
  and set `SENSOR_CONTENT_TRIVY_DB_REPOSITORY=harbor.internal/aquasec/trivy-db:2`.
- nuclei templates: put `nuclei-templates-vX.Y.Z.tar.gz` and the release's
  `nuclei-templates-X.Y.Z_checksums.txt` on an internal web server or a
  mounted directory, set `SENSOR_CONTENT_NUCLEI_TEMPLATES_URL=file:///mirror/nuclei-templates-{version}.tar.gz`,
  `SENSOR_CONTENT_NUCLEI_TEMPLATES_CHECKSUMS_URL=file:///mirror/nuclei-templates-{bare_version}_checksums.txt`
  and pin the version (policy or `SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION`).
- semgrep: `SENSOR_CONTENT_SEMGREP_RULES_PATH=/mirror/semgrep-rules.yaml`.

**Disk:** about 1.5 GB per trivy DB version (two with the default
`SENSOR_CONTENT_KEEP=1`, plus 0.8 GB each with the Java DB), about 150 MB per
nuclei-templates version (the baked one lives in the image), a few MB of semgrep rules.

## Validation (CTEM Stage-4)

Beyond one-shot scanning, the daemon can **re-verify existing findings** so the
platform can confirm-or-downgrade them without a full rescan.

- **`validate`** — advertised **always**. The daemon wraps its command executor
  with a validating executor that runs a non-intrusive TCP-reachability
  safe-check for `validate` commands, regardless of which scanners are enabled
  (`runDaemon` in `main.go`).
- **`validate:nuclei`** — advertised when the vuln-scan (nuclei) image is present
  It re-runs a finding's **own** detection template
  non-destructively and returns `detected` / `not_detected` / `inconclusive` /
  `error` (`internal/executor/validation.go` `RunNucleiValidate`). If the
  template is not installed, the result is `inconclusive` — never a false
  downgrade.
- **`retest:nuclei`**: advertised with `validate:nuclei`. The platform's
  `retest` command lists nuclei findings (the template id of each, and the
  address it is on). The `nuclei-validate` tool checks each address first
  with a TCP connect, then re-runs each finding's own template with the
  re-verification's safety flags. A finding whose template matches again is
  `still_present`. One whose template ran against the reachable address and
  did not match is `fixed`. Anything else is `unverifiable`, including an
  unreachable address and a template that is not installed or is excluded.
  The platform closes or reopens findings from these verdicts. The command
  passes the local policy like a scan (`checks.allow` must list `retest` when
  the policy lists check types), and every address passes the validate guard
  (no loopback, link-local or cloud-metadata target).

## One job, then exit (Kubernetes Job)

`-job <command id>` (or `SENSOR_JOB_ID`) runs the one platform command with
that id and exits, so a launcher can start one sensor pod per job. It implies
`-daemon -enable-commands`. The sensor:

1. sets up as a daemon does: identity, manifest, tools, local policy, outbox,
   and heartbeats, which keep the job's lease and carry cancels;
2. claims the command by id;
3. runs it with every check a polled command gets (kill switch, served
   command types, expiry, local policy, the platform's tool policy);
4. waits up to 5 minutes for the outbox to deliver the results;
5. exits.

It takes no other work.

| Exit | When |
|---|---|
| `0` | the job ran and its results were delivered. A scan that failed is reported to the platform as failed; retrying the pod would not change it. |
| non-zero | the platform refused the claim (another tenant's command, held by another sensor, no longer pending), the job was not run (it is released for another sensor), or results were not delivered in time |

Mount the outbox (`SENSOR_OUTBOX_DIR`) on a persistent volume. Results that are
not delivered before the pod ends are otherwise lost. On SIGTERM the job is
stopped and handed back to the platform.

```yaml
apiVersion: batch/v1
kind: Job
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: sensor
          image: ghcr.io/openctemio/sensor:<version>
          args: ["-job", "$(JOB_ID)"]
          env:
            - {name: JOB_ID, value: "<command id>"}
            - {name: API_URL, value: "https://openctem.example"}
            - {name: SENSOR_OUTBOX_DIR, value: /var/lib/openctem/outbox}
          volumeMounts:
            - {name: outbox, mountPath: /var/lib/openctem/outbox}
      volumes:
        - name: outbox
          persistentVolumeClaim: {claimName: sensor-outbox}
```

## Tenable.sc connector

The sensor can pull hosts, vulnerabilities and plugin metadata from a
Tenable.sc in your network, with the Tenable API keys kept on the sensor
(api RFC-047): [`docs/TENABLE_SC.md`](docs/TENABLE_SC.md). Configure it with
`-tenable-sc-config` (or `SENSOR_TENABLE_SC_CONFIG`, or the `TENABLE_SC_*`
environment shorthand).

## Sensor-local policy

The owner of the scanned network sets what this sensor may do, in a
read-only file the platform cannot change (api RFC-040 §5.7):
[`docs/LOCAL_POLICY.md`](docs/LOCAL_POLICY.md), template
[`docs/sensor-policy.example.yaml`](docs/sensor-policy.example.yaml).

```bash
install -o root -g root -m 0644 docs/sensor-policy.example.yaml /etc/openctem/sensor-policy.yaml   # then edit it
docker run … -v /etc/openctem:/etc/openctem:ro ghcr.io/openctemio/sensor:<tag> -daemon -enable-commands
touch /etc/openctem/STOP   # kill switch: no job runs until the file is removed
```

Every job is checked after the claim and before any tool runs: its targets
(host names resolved, every address checked), ports, tool, job type, custom
templates and interactsh. A refused job is reported failed with
`refused by local policy: <rule>: <detail>`. Rate and run time are capped.
A malformed policy stops the sensor. Without a policy the sensor works as
before, reports `local_policy: absent` and logs warnings; custom templates
and interactsh are off in any policy unless it turns them on.

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

- **Dangerous-flag blocklist** (sdk-go `core.ValidateExtraArgs`, CWE-77) — rejects
  user-supplied tool flags that redirect output, set a proxy, load an
  attacker-controlled target list / rule / template file, enable the code,
  file, self-contained or headless template types, switch template signature
  checks off, upload results to a third party, or override resolvers /
  interface / source IP. Rate-limit flags are refused too (see below).
- **Nuclei re-verify is detection-only** — the `dos`, `fuzz`, `intrusive`,
  `brute-force` and `default-login` template tags are excluded, the template must have a safe
  matcher, runs are bounded by timeout and rate-limited per asset, and every run
  is logged under its command id (the audit key).

### Nuclei template trust and rate limits

The sensor's own nuclei templates (the managed `nuclei-templates` release,
or the templates baked into the image) always run with
`-disable-unsigned-templates`: nuclei skips any template whose
ProjectDiscovery signature is missing or does not match. The code protocol
is never enabled: the sensor never passes `-code`, `-file`, `-esc` or
`-dast`, passes `-headless` only when configured in code, and refuses all of
them (and `-dut=false`) in extra args.

**Non-intrusive only** (api RFC-036, tier T1). Every nuclei run, of the
sensor's own templates or of custom templates, gets
`-etags intrusive,default-login,dos,fuzz,fuzzing,bruteforce,brute-force,local,txt-service`
on the command line (with or without managed templates), plus any tags the
operator or the scan excludes. A scan whose `tags` setting names one of
these classes fails with the reason instead of running; a scan's
`exclude_tags` only adds to the list; and `-itags` / `-include-tags`, the
only nuclei flags that re-admit an excluded template, are refused in extra
args (nuclei v3.11.1 drops an `-etags` template however it was selected:
directory, explicit `-t` file, `-id` or `-tags`). Re-verifications exclude
`default-login` as well. There is no intrusive mode yet: one needs an
approved, owner-ceilinged grant on the command (RFC-036 T2), which the
platform and the sensor do not have.

Custom templates (uploaded by a tenant admin on the platform) are not signed
by ProjectDiscovery, so they are trusted another way:

1. The platform refuses, at upload, templates that use the `code`,
   `javascript`, `headless` or `file` protocol or are self-contained.
2. When it hands a command to a sensor, the platform validates every
   template again and signs one manifest of the set (tenant, this sensor,
   this command, issue and expiry time, and the id, name, type and SHA-256
   of each template) in a DSSE envelope with an Ed25519 key derived for the
   tenant. The sensor (sdk-go) verifies the envelope against
   `SENSOR_TEMPLATE_SIGNING_KEYS` before parsing it, then refuses a manifest
   for another command (or another sensor, when `SENSOR_ID` is set), an
   expired one, and any template changed, added, held back or reordered.
   Without a pinned key, scans with custom templates fail.
3. The sensor checks the templates itself again (`CheckCustomTemplates`):
   the same protocols and self-contained templates are refused.
4. Custom templates run in their own nuclei run, with
   `-exclude-type code,file,headless,javascript` and never `-headless`;
   the sensor's own templates run before them, still with
   `-disable-unsigned-templates`. The scan's results are both runs'.

Pin the key once per sensor:

```bash
# On the platform, as a tenant admin:
curl -H "Authorization: Bearer $TOKEN" https://platform/api/v1/scanner-templates/signing-key
# -> {"algorithm":"ed25519","key_id":"…","public_key":"<base64>"}
docker run … -e SENSOR_TEMPLATE_SIGNING_KEYS=<base64> ghcr.io/openctemio/sensor:<tag>
```

To roll the platform key, pin the new key next to the old one
(comma-separated), rotate on the platform, then drop the old one.

**Rate limits.** nuclei always gets `-rate-limit`, `-c` and `-bs`. A scan
command may ask for lower values (config `rate_limit`, `concurrency`,
`bulk_size`); the sensor uses them up to the ceilings
`SENSOR_NUCLEI_MAX_RATE_LIMIT` / `_CONCURRENCY` / `_BULK_SIZE` (default
150 / 25 / 25, nuclei's own defaults) and never above. A value outside
1..1000000 stops the sensor at start. Rate-limit flags in extra args
(`-rate-limit`, `-bs`, `-c`, `-per-host-rate-limit`, ...) are refused.
Re-verification (`validate:nuclei`) runs at 20 requests per second, or the
ceiling when it is lower.

## Upgrading from the agent release

The binary, images and settings were renamed from *agent* to *sensor*
([RFC-023 §9.5](https://github.com/openctemio/openctem/blob/main/api/docs/rfcs/RFC-023-scan-zones-and-scanners.md)).
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
**different** values; the error names both (never the values). The sensor
negotiates the protocol with the platform (v2 where offered, v1 otherwise), so
an upgraded sensor works with any platform version.

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

- [openctemio/openctem](https://github.com/openctemio/openctem) - the platform: API (`api/`) and web console (`web/`), formerly openctemio/api and openctemio/ui
- [openctemio/sdk-go](https://github.com/openctemio/sdk-go) - Go SDK

## License

Apache License 2.0 - see [LICENSE](LICENSE).
