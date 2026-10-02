# Changelog

All notable changes to the OpenCTEM agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline builds from a `v*` tag: `.github/workflows/release.yml`
runs GoReleaser to produce archives for linux/amd64, linux/arm64 and
darwin/arm64 with checksums, and `docker-publish.yml` builds the multi-arch
image. Both are gated on the tag — nothing is published without one.

## [Unreleased]

### Changed: the renewed API key survives a restart; renewal on by default on persistent state

- With sdk-go's sensorkit (openctemio/sdk-go#104) the daemon reads and
  writes its API key in the state directory (`SENSOR_STATE_DIR`, default
  `/var/lib/openctem/state`): a renewed key is saved there and preferred
  over `API_KEY` on the next start, unless `API_KEY` was changed to a
  regenerated key (api RFC-032 Phase 0). A
  `~/.openctem/sensor-credentials.json` from an earlier version is moved
  there. The tool cost history moves to the state directory too.
- Key auto-renewal defaults to **on when the state directory is on a
  persistent volume** (or outside a container) and off otherwise, with the
  reason logged. `PLATFORM_KEY_AUTORENEW=true|false` or `-key-autorenew` /
  `-key-autorenew=false` force it.
- The images create `/var/lib/openctem/state` (0700, the sensor user) and
  declare `/var/lib/openctem/content` a volume next to the outbox; state is
  deliberately not a `VOLUME` (an anonymous volume is lost with the
  container). Mount a named volume or a PVC at
  `/var/lib/openctem/state`.
- Every heartbeat carries the process's `instance_id` (sdk-go), so the
  platform flags a key running in two places.

### Changed: the daemon runs on the SDK's sensor runtime (sdk-go `pkg/sensorkit`)

- The platform plumbing moved into sdk-go `pkg/sensorkit`: settings
  resolution, `AGENT_*` migration, heartbeat, doorbell, key renewal, startup
  auth wait, command poller and slots, outbox, and drain. Any sensor gets it
  with one call, so this repository keeps only its tools: scanners,
  executors, scanner content and image tool probing.
- **Nothing changes for operators.** Flags, environment variables, exit
  codes, log lines and the v1/v2 wire are the same. A recorded fake
  platform shows the same requests and heartbeat bodies before and after,
  in 14 scenarios.
- One small difference: a scanner whose name was retired (`gitleaks`) logs
  its "replaced by" note once instead of once per internal lookup.
- New, optional: `SENSOR_CA_CERT_FILE` names a PEM file with the platform's
  private CA. That CA is then trusted for platform requests, in addition to
  the system roots.


### Changed: the sensor finds its own tools; `SENSOR_TOOLS` is optional

- A server-controlled daemon (`-daemon -enable-commands`) given no tool list
  (no `-tool`, `-tools`, `SENSOR_TOOLS` or config-file scanners) probes the
  native scanners (semgrep, betterleaks, trivy, nuclei) at start-up and
  runs the ones that are installed. It logs them ("Tools: ... (detected; set
  SENSOR_TOOLS to limit)") and reports them on every heartbeat. The image
  variant decides the tool set. The platform needs no tool list for a
  sensor (api RFC-029 §4.3.1).
- `SENSOR_TOOLS` / `-tools` still works, now as an optional operator
  allowlist: only those scanners run and are reported. The `-default` image
  no longer sets it. An explicit list behaves exactly as before.
- The heartbeat inventory is the SDK's tool registry (`BaseSensor.Tools`,
  sdk-go#99) instead of the daemon's own reporter. The report is the same,
  and each tool also carries `kind: scanner`.
- `-content-status` / `-content-refresh` without a list use the installed
  tools.

### Security: signed images and release archives

- Every image `docker-publish.yml` pushes is signed by digest with cosign
  keyless signing (`--recursive`: the multi-platform index and each
  platform's manifest), then verified in the same job; the Docker Hub copies
  are signed too. `release.yml` signs `checksums.txt`
  (`checksums.txt.sigstore.json`). The certificate names the workflow at the
  release tag, so `cosign verify --certificate-identity ...` proves an image
  or archive was built by this repository's release pipeline (README,
  "Verifying images and releases"). This is the trust root the platform's
  managed sensor updates rely on (api RFC-031).

### Added

- **The daemon reports what it really has** (api RFC-029 §4.3.1). Every
  heartbeat lists every configured scanner, with its version from the
  scanner's own install check (`installed: false` when it is missing or
  fails to run) and its content. It also lists the capabilities the daemon
  serves: each installed tool's name, its sast/sca/secrets/iac/container/dast
  category, `validate`, and `validate:nuclei` with nuclei, when commands are
  on. When an operator cap is set (`sensor.max_jobs`, `-max-concurrent`,
  `SENSOR_MAX_JOBS`), the heartbeat reports it as `max_concurrent_jobs`.
  The platform dispatches by the report: a scan for a tool goes only to
  sensors that have it, and its administrator can only narrow the report.
  Tools are probed at start and at most every 10 minutes.
- **Managed scanner content** (api RFC-031). The daemon refreshes the trivy
  vulnerability DB, the nuclei templates and (when rulesets are chosen) the
  semgrep rules on a schedule and on the platform's `refresh_content`
  command; verifies each download (OCI digest and trivy metadata,
  release-checksum sha256 and a nuclei load check, a semgrep load check),
  swaps it in atomically and keeps the previous version. Scans use exactly
  the current version (`--cache-dir … --skip-db-update`, `-t … -disable-update-check
  -disable-unsigned-templates`, `--config <rules>`), so trivy no longer
  downloads its DB mid-scan and nuclei no longer updates its templates by
  itself. The heartbeat reports each tool and its content
  (`tools[].content`), results carry `tool.properties.content`. Mirrors and
  local files for air-gapped hosts; the platform's policy can pin versions
  and set a maximum age but never a source. `SENSOR_CONTENT=off` restores
  the old behaviour. See "Scanner content updates" in the README.
- `-content-status`, `-content-refresh` and `-content-force`.
- Content reports `checked_at` (the last check that confirmed it is the
  newest or pinned version); old content whose source has nothing newer is
  no longer stale (sdk-go `ContentInfo.Stale`). A pinned nuclei-templates
  release carries its publication date; a pin added, changed or removed
  moves the content; every `refresh_content` result lists each content in
  exactly one of refreshed/unchanged/skipped (with a reason)/failed; one-shot
  and scheduled results carry `tool.properties.content` too.

### Upgrading to protocol v2 (read this)

The OpenCTEM platform (api v0.9.0) serves the whole sensor protocol under
`/api/v2/sensor/*` and deprecates the old `/api/v1/agent/*` routes
(`Deprecation`, `Sunset: Thu, 01 Apr 2027 00:00:00 GMT`; api RFC-029). This
release speaks v2 for everything such a platform offers.

- **Running our sensor:** use this release (`ghcr.io/openctemio/sensor:v0.5.0`,
  or `go install github.com/openctemio/sensor@v0.5.0`). No configuration
  change. Against an older platform it falls back to v1 by itself.
- **Check:** the platform's Sensors page shows the sensor on protocol v2, or
  `GET /api/v1/sensors/{id}` returns `"protocol": {"version": 2, ...}` after
  its next heartbeat. A sensor still on v1 is shown as deprecated.
- `SENSOR_PROTOCOL=v1` keeps the old requests byte for byte (and logs a
  deprecation warning once when the platform deprecated them).

### Changed

- **Protocol v2 for the whole sensor surface** (sdk-go v0.9.0, api RFC-029):
  heartbeat, command poll and claim/start/complete/fail, suppressions (the
  `-fail-on` gate), fingerprint check and PR baseline-diff, and key renewal
  (`-key-autorenew`) use `/api/v2/sensor/*` when the platform lists them on
  `GET /api/v2/sensor/hello`; results did since v0.4. The sensor is
  identified by its key alone: no `X-Agent-ID` on v2. Command transitions are
  idempotent on v2, so a completion whose answer was lost no longer fails the
  command.
- `-protocol` / `SENSOR_PROTOCOL` / `server.protocol` now name the sensor
  protocol, not only the results protocol; values are unchanged.
- Requests carry `User-Agent: openctemio-sensor/<version> openctem-sdk-go/<version>`,
  which the platform shows per sensor next to its protocol.

### Fixed

- **No duplicate scans from over-claiming** (api RFC-030 Phase 0, sdk-go
  #92). The daemon takes a free slot before it claims a command, asks the
  platform for no more commands than its free slots, and does not run a
  command whose start the platform refused. Before, it claimed up to 10
  commands with 5 slots; the platform re-queued the waiting ones after 10
  minutes and another sensor scanned the same assets.
- **Concurrency follows the resources, no fixed 5** (sdk-go #93). The daemon
  sizes its slots from the CPU and memory it may use (cgroup v2/v1 aware)
  and its tools' learned cost, halving after OOM kills, timeouts or CPU
  throttling; the cost history is kept in `tool-costs.json` in the state
  directory (`SENSOR_STATE_DIR`, default the outbox's parent,
  `/var/lib/openctem` in the images). `-max-concurrent`, `SENSOR_MAX_JOBS`
  or `sensor.max_jobs` (1-100) is now a cap, not a count; unset means no
  cap (platform mode keeps 5). The heartbeat reports the cap
  (`max_concurrent_jobs`), the live slots and per-tool costs (`capacity`),
  the resources (`resources`), the local queue (`queue`) and the held
  command ids (`running`).
- **SIGTERM really drains** (api RFC-030 E2E F3/F4). The daemon exited at
  once on SIGTERM, before the poller could drain: running scans were left
  `running` on the platform and their processes outlived the sensor. It now
  waits for the drain (`SENSOR_DRAIN_GRACE`, default 30s): running scans
  finish, or are stopped (their whole process group, sdk-go #97) and
  released to the platform. A second signal stops at once. Orchestrators
  should allow the grace plus ~15 s before SIGKILL (Docker
  `stop_grace_period`, Kubernetes `terminationGracePeriodSeconds`; Docker's
  default is 10 s).
- **The first heartbeat precedes the first poll** (F2) and carries the
  capacity report, so the platform knows the sensor's cap before handing
  it work. A command's slot is reused only after its result reached the
  platform (sdk-go #95, F1).
- **Graceful stop** (sdk-go #93): on SIGTERM the daemon stops claiming,
  lets running scans finish for 30 s, then cancels them and releases them
  to the platform so another sensor takes them at once; a command the
  platform cancels is stopped and released. Per-host politeness: one
  command per target host at a time unless the command allows more.
- **Platform mode: a failed scan is reported failed** (api RFC-030 B12). A
  nuclei/trivy/semgrep run that exited with an error, timed out or was
  killed was reported `completed` with 0 findings, i.e. "scanned clean";
  findings that could not be delivered were also reported `completed`.
- **Sensors report their version and hostname** (sdk-go v0.8.1). The heartbeat
  never filled them, so the platform's Sensors page showed "No host info".

### Changed

- **Results use protocol v2 when the platform offers it** (sdk-go v0.8.0,
  api RFC-026). `SENSOR_PROTOCOL` / `-protocol` / `server.protocol`:
  `auto` (default; asks on the heartbeat, falls back to v1 against an older
  platform), `v1` (byte for byte the old requests) or `v2`.
- **The Go module is `github.com/openctemio/sensor`** (was
  `github.com/openctemio/agent`; the repository was renamed), so
  `go install github.com/openctemio/sensor@latest` works. Docs, CI
  templates and image source labels point at `openctemio/sensor`; the frozen
  `ghcr.io/openctemio/agent:*` images are unchanged.
- sdk-go v0.8.0 (the tag).
- `-retry-queue` / `RETRY_QUEUE=true` now turn the outbox on (also for a
  one-shot run); `RETRY_DIR` is imported from once. The old retry queue is gone.

- **Betterleaks replaces gitleaks as the secret scanner.** Betterleaks is
  gitleaks' successor by its original author: v1 keeps the gitleaks CLI,
  config format and JSON report, and adds BPE-token filtering, Expr filters
  and validation, recursive decoding and archive scanning. The images bundle
  betterleaks 1.9.0 (SHA-256 pinned per architecture), the `-gitleaks` image
  variant is now `-betterleaks` (old `-gitleaks` tags stay pullable, frozen),
  the `-default` image's `SENSOR_TOOLS` is `semgrep,betterleaks,trivy,nuclei`,
  and the CI templates use `betterleaks`. A command, config or template that
  says `gitleaks` runs betterleaks (sdk-go `core.CanonicalScannerName`).
  Fingerprints of secrets both tools report do not change. See
  [Upgrading: gitleaks → Betterleaks](README.md#upgrading-gitleaks--betterleaks).
- **The scanner no longer prints raw secrets into the sensor log.** In
  verbose mode the tool ran with `--verbose`, which prints each finding with
  its secret; it no longer does.
- The repository's own secret scan (Security workflow, pre-commit, `make
  security-scan`) uses betterleaks; the workflow job runs on every push and
  pull request and uploads SARIF (the gitleaks-action job was opt-in behind a
  licence and never ran).

### Fixed

- **The retry queue was never on**: `-retry-queue` / `RETRY_QUEUE=true`
  created nothing (the SDK ignored the setting) and the daemon logged
  "Could not start retry worker". Replaced by the outbox (Added).
- **A command was reported complete before its results arrived**, or even
  when they failed. The command result now waits behind its results and
  turns "failed" when the platform refuses them.
- **Scheduled daemon scans and platform-mode scans file findings on the
  scanned repository.** Their findings had no asset, which protocol v2
  rejects; dispatched and one-shot scans already named it.

- **A rejected API key no longer restart-loops the daemon.** It exited on a
  401 at start-up, and the container restart policy relaunched it at once (12
  restarts and 12 requests in 3 minutes under `docker --restart=always`, each
  repeating the plain-http warning). The daemon now stays up, stops polling
  and re-checks with a capped backoff (30 s doubling to 10 min), logging one
  actionable line per attempt without `-verbose`, and resumes on its own once
  the key is accepted. Mid-run rejections (revoked, regenerated or deleted
  sensor) back off the same way instead of a heartbeat and a poll every
  interval. A 401 `API key required` says that `API_URL` points at the web UI
  or a header-stripping proxy.
- **One-shot runs exit with code 78 (`EX_CONFIG`) on a rejected key**, with
  the same message.
- **Daemon start-up sends one heartbeat, not two**: the first heartbeat is the
  connection check.
- **semgrep works in the images again.** Every v0.3.0 image that bundles
  semgrep (`-default`, `-ci`, `-semgrep`) shipped semgrep 1.93.0, whose
  opentelemetry-instrumentation 0.46b0 imports `pkg_resources`; setuptools
  81 removed it, so `semgrep --version` died with `ModuleNotFoundError` and
  the sensor skipped semgrep ("Scanner semgrep not installed, skipping").
  The images now install semgrep 1.178.0 against a pinned dependency set
  (`docker/semgrep-constraints.txt`), and the build runs `semgrep --version`.
- **The `-default` image connects with its own defaults.** Its command was
  `-platform -verbose`, a mode that uses `/api/v1/platform/register`,
  `lease` and `poll`, which the API does not serve. The default is now the
  server-controlled daemon, `-daemon -enable-commands -verbose`, running the
  tools in the new `SENSOR_TOOLS` variable (the image sets
  `semgrep,gitleaks,trivy,nuclei`; `-tool`/`-tools` still win).
- **A server-controlled daemon without `API_URL`/`API_KEY` says so.** It
  used to start, never poll, and never say why. It now exits with code 2,
  names the missing variables and shows how to set them.
- **A broken tool is no longer reported as "not installed".** The sensor
  tells a missing binary from one that is installed but fails to run, and
  prints the tool's own error ("Scanner semgrep skipped: installed but fails
  to run: ... ModuleNotFoundError: No module named 'pkg_resources'").
  `-check-tools` shows `INSTALLED BUT BROKEN`, and `-list-tools` now shows
  each native scanner's state (`available: <version>`, `not installed`,
  `BROKEN: ...`) and lists nuclei.

### Added

- **Durable outbox (on by default with `-daemon`).** Every result is written
  to `/var/lib/openctem/outbox` (else `~/.openctem/outbox`) before it is
  sent and deleted only once the platform accepted it: a crash, `kill -9`,
  an API outage or a restart loses nothing, and the backlog is delivered
  oldest first as soon as a heartbeat gets through. Refused results go to
  `dead/` with the reason; a 1 GiB / 7 day cap drops the oldest with a
  warning. Files are 0600, encrypted (AES-256-GCM, key created on first
  start), one sensor per directory. Settings: `SENSOR_OUTBOX` (on/off),
  `SENSOR_OUTBOX_DIR` / `-outbox-dir`, `SENSOR_OUTBOX_MAX_BYTES`,
  `SENSOR_OUTBOX_MAX_AGE`, `SENSOR_OUTBOX_KEY_FILE`, or the `outbox:`
  config block. `-outbox-status` and `-outbox-requeue-dead` inspect it.
  The heartbeat reports its state to the platform.
- **The `default`, `full` and `slim` images declare
  `VOLUME /var/lib/openctem/outbox`**, owned by the image's non-root user.
  Mount a named volume there (README and QUICK_START show `docker run` and
  Compose).

- **Image smoke test.** `scripts/image-smoke-test.sh` runs every bundled
  tool's version command and checks `-list-tools` reports each one
  available (and, for `-default`, the default command and the missing-
  credentials error). It runs for every variant on pull requests that touch
  the images (`image-smoke.yml`) and gates `docker-publish.yml` before any
  image is pushed.

## [v0.3.0] — 2026-10-01

First release under the *sensor* name (binary `openctemio-sensor`, images
`ghcr.io/openctemio/sensor:v0.3.0-<variant>`). The previous release was
v0.2.2 (2026-08-20, still named *agent*).

### Renamed: agent → sensor (RFC-023 §9.5)

The binary, images and settings move to the *sensor* vocabulary. Existing
installations upgrade in place with no manual step; the sensor refuses to
start only when an old and a new name are set to different values (the error
names both, never the values).

| Before | After | Upgrade |
|---|---|---|
| binary `agent` | `openctemio-sensor` (archives `openctemio-sensor_<version>_<os>_<arch>`) | — |
| images `ghcr.io/openctemio/agent:*` | `ghcr.io/openctemio/sensor:*` | old tags stay pullable and **frozen**: never re-pushed, never deleted |
| `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` | `SENSOR_ID`, `SENSOR_NAME`, `SENSOR_ALLOW_PRIVATE_TARGETS` | old name applied, startup `WARN deprecated configuration` naming both |
| `-agent-id` | `-sensor-id` | old flag applied, warning |
| `-config` file `agent:` block, `server.agent_id` | `sensor:`, `server.sensor_id` | old keys applied, warning |
| `~/.openctem/agent-credentials.json` | `~/.openctem/sensor-credentials.json` | moved on first start by the SDK: written 0600 with fsync, read back and compared, then the old file removed; same identity and key, no re-registration; used in place if it cannot be moved (read-only mount); `-credentials <path>` used as is |
| `API_URL`, `API_KEY`, `BOOTSTRAP_TOKEN` | unchanged | — |
| CI templates (`ci/`) | image `ghcr.io/openctemio/sensor:latest-<variant>`, command `openctemio-sensor` | — |

Built on sdk-go's sensor release (v0.7.0; until it is tagged, a pseudo-version
of its `refactor/sensor-rename` branch). The protocol v1 wire is unchanged, so
this sensor works with platforms from before and after the rename. The Go code
was renamed by `scripts/rename/sensor-rename.sh` (re-runnable, type-aware).
The repository itself keeps the name `openctemio/agent` until its owner renames
it.

### Added

- **Heartbeat doorbell** (API RFC-023 §9.2a, sdk-go v0.7.1). A daemon
  (`-daemon -enable-commands`) no longer polls for commands every 30 s when
  the platform supports the doorbell: it polls when a heartbeat reports
  waiting work (`pending_jobs`), plus a safety poll every 5 minutes, and
  heartbeats as often as the platform advises. `pause` (a disabled sensor)
  stops it taking new jobs while running jobs finish and heartbeats go on
  (logged as "paused by platform"); the first heartbeat without `pause`
  resumes it; `drain` is final until restart. Against an older API it polls
  every `command_poll_interval` as before. Opt out with `-disable-doorbell` /
  `sensor.disable_doorbell: true`.
- `-key-autorenew` now works in daemon mode too: the key is renewed at half
  its lifetime and at once when the platform's heartbeat asks (`rotate_key`),
  and saved to the `-credentials` file, whose key the next start uses.

- **Executors** — safe-check validation executor (RFC-011), Tenable runner mode
  (RFC-007 §3.10), and a risk-aware CI gate that blocks on actively-exploited
  findings below the configured threshold.
- **PR-scoped scanning** — baseline-diff so a pull-request scan reports only what
  the PR introduces, with results posted back as comments (RFC-008 Phase 3).
- **Auto-resolve for manual scans** — a full-repo scan outside CI now closes
  findings it no longer sees, matching the CI path.
- **Agent API-key auto-renewal** (RFC-014 Phase 2) — the agent renews its own
  credential before expiry rather than failing closed at rotation time.
- **Asset-name normalisation in recon parsers** (RFC-001), so discovered assets
  correlate with what the platform already knows instead of arriving as
  near-duplicates.
- **`--allow-private-targets`**, opt-in, for scanning internal networks. Off by
  default; see the SSRF guard below for what it relaxes and what it cannot.
- Multi-arch Docker publish and image security scanning.

### Security

- **Scanner target SSRF guard.** Two tiers: a hard block that no flag can open
  (cloud metadata endpoints, loopback, CGNAT, multicast, broadcast, IPv6
  link-local) and a soft block for RFC1918 + IPv6 ULA that
  `AGENT_ALLOW_PRIVATE_TARGETS` opts out of. Shared design with
  `api/pkg/httpsec` and `sdk-go/pkg/httpsec`; CI asserts the three CIDR tables
  stay in parity.
- **`dangerousToolFlags`** — an explicit deny-list of scanner flags that would
  turn a scan into arbitrary execution or a file read on the agent host.
  Completeness is CI-enforced.
- **Runner target-guard** (RFC-007 §8 R1) — blocks metadata and loopback
  targets and bounds scan ranges, so a runner cannot be pointed at the host it
  runs on.
- **`ExtraArgs` validation and bounds checking**, closing the gap where
  operator-supplied arguments reached a scanner unchecked.
- **Supply-chain verification in the image build** — gitleaks, trivy, nuclei and
  semgrep binaries are SHA-256 verified against published checksums at build
  time, so a compromised upstream download does not silently become part of the
  image.
- **Agent audit fixes** — SSRF guard, gate now fails closed rather than open, a
  secret leak in output, and scan bounds.
- **Go toolchain kept current for stdlib CVEs** — 1.25.7 (GO-2026-4337), 1.25.8,
  then 1.26 (five stdlib vulnerabilities). Currently `go 1.26`.

### Fixed

- **The sensor connects to a platform on a private network again** (sdk-go
  v0.7.2). Since v0.2.x a platform on loopback, a Docker or Kubernetes
  network, RFC1918, ULA or Tailscale/CGNAT addresses was refused with
  `ssrf guard: blocked IP` on every heartbeat unless
  `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE=1` was set. That setting is no longer
  needed to reach the platform; remove it unless you want scanners to reach
  private targets too (that is `SENSOR_ALLOW_PRIVATE_TARGETS=1`).
  `HTTPS_PROXY` / `NO_PROXY` are honored for platform traffic again.
- **A misread scan-target setting stops the sensor at startup** (sdk-go
  v0.7.3). `SENSOR_ALLOW_PRIVATE_TARGETS` only accepts `1`; `true`, `yes` or
  `on` used to be ignored silently, refusing every private target. The
  sensor now exits with a message naming the variable, as it does when the
  sensor and pre-rename (`AGENT_*`) names disagree.

- **Scans dispatched by the server now deliver their findings.** Before, the
  command lifecycle completed but no results arrived:
  - nuclei output had no parser and the SARIF fallback read it as 0 findings
    (or failed). The nuclei parser is registered, and output no parser reads
    now fails the command instead of reporting 0 findings.
  - gitleaks, semgrep and trivy fs targets were refused ("DNS lookup failed for
    scanner target /…/repo"): the SSRF guard resolved filesystem paths as
    hosts. Targets are now checked by scanner type; code-scanner paths are
    confined to the scan workspace (`SENSOR_SCAN_ROOTS`, default the working
    directory) instead.
  - every custom-template scan failed with a hash mismatch (sdk-go hashed the
    base64 text; the platform hashes the template).
  - chunked uploads attributed later chunks to tool `unknown` on a placeholder
    asset (sdk-go now makes every chunk self-describing).
  - a dispatched filesystem scan's findings now land on the repository asset
    (its git remote) rather than a placeholder.
- A daemon with `-enable-commands` no longer scans its working directory with
  every configured scanner at start and hourly; it scans only what the server
  dispatches, plus targets configured explicitly.
- CI templates referenced Docker Hub images that were never published
  (`openctemio/sensor:ci` and others). They now use
  `ghcr.io/openctemio/sensor:latest-<variant>`, and the release pipeline
  publishes a `ci` variant (semgrep + gitleaks + trivy) for the full-scan job.
  GitLab jobs override the image entrypoint, which is the sensor binary.
- pgx bumped to v5.11.0 (CVE-2026-33815, CVE-2026-33816, CVE-2026-41889; an
  indirect dependency). x/crypto stays at v0.57.0, the latest: GO-2026-5932
  has no fixed release yet.
- The weekly security sweep never scanned the container image: the job was
  gated on `event_name == 'push'`, so the scheduled run skipped it and reported
  green. It had been reporting green without scanning for weeks.

### Tools invoked

`gitleaks`, `httpx`, `nuclei`, `semgrep`, `subfinder`, `trivy` — each behind the
target guard and flag deny-list above.

---

## Before this file

The agent has no tagged history. Commits before this point are visible with
`git log`, and the platform components it talks to have their own tags —
`api` and `ui` at v0.3.0, `sdk-go` at v0.5.2, `ctis` at v1.1.0.
