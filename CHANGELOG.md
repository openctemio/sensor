# Changelog

All notable changes to the OpenCTEM agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline builds from a `v*` tag: `.github/workflows/release.yml`
runs GoReleaser to produce archives for linux/amd64, linux/arm64 and
darwin/arm64 with checksums, and `docker-publish.yml` builds the multi-arch
image. Both are gated on the tag — nothing is published without one.

## [Unreleased]

Everything below is on `main` and not yet tagged; the last release is
v0.2.2 (2026-08-20, still named *agent*). This section becomes the notes for
the next release.

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
