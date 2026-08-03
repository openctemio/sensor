# Changelog

All notable changes to the OpenCTEM agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline builds from a `v*` tag: `.github/workflows/release.yml`
runs GoReleaser to produce archives for linux/amd64, linux/arm64 and
darwin/arm64 with checksums, and `docker-publish.yml` builds the multi-arch
image. Both are gated on the tag — nothing is published without one.

## [Unreleased]

Everything below is on `main` and has never been tagged, so **no agent binary
or image has ever been published by the release pipeline.** 86 commits. The
`openctemio/agent:demo-ci-fixed` image in use today was built by hand.

This section becomes the notes for the first tagged release.

### Added

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
