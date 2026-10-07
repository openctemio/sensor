# syntax=docker/dockerfile:1.7
# =============================================================================
# OpenCTEM Sensor - Main Dockerfile
# =============================================================================
# This file contains:
#   - Builder stages (shared by all images)
#   - Combined images (slim, full, platform)
#
# For per-tool images, see:
#   - Dockerfile.semgrep  (SAST)
#   - Dockerfile.betterleaks (Secrets)
#   - Dockerfile.trivy    (SCA/IaC/Container)
#   - Dockerfile.nuclei   (DAST - NOT for CI, separate workflow)
#
# Docker Image Strategy:
#   - CI scanning is not here: openctemio/ci builds the CI images
#     (ghcr.io/openctemio/ci-<tool>, ghcr.io/openctemio/ci).
#   - Platform (default) image: the daemon with nuclei and the recon tools
#     subfinder, dnsx, naabu, httpx and katana; no CI tools.
#   - Full image: every tool (local development).
#   - Per-tool images (semgrep, trivy, betterleaks, nuclei): a daemon with one tool.
#
# Build examples:
#   docker build --target slim -t openctemio/sensor:slim .
#   docker build --target full -t openctemio/sensor:full .
#   docker build --target platform -t openctemio/sensor:platform .
#
# =============================================================================

# pip ships in the python base image; its bundled version carries known CVEs
# (pip < 26.2), so the tools-ci build stage installs semgrep with this pinned
# release. No runtime image keeps pip: each one deletes it after copying the
# tools' site-packages, so nothing in a running sensor can install packages.
ARG PIP_VERSION=26.2.1

# Base images are pinned by digest (tag kept for readability). Dependabot
# cannot query ECR Public (see .github/dependabot.yml), so refresh them by hand:
#   docker buildx imagetools inspect <image>:<tag>   # the index "Digest:"
# and bump every FROM of that image in all five Dockerfiles together. The
# weekly "Docker Image Scan" (security.yml) reports base-image CVEs that call
# for a refresh.

# -----------------------------------------------------------------------------
# Stage: Build Go binary (standalone - for public distribution)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS builder

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY . /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/openctemio-sensor \
    . \
    && mkdir -p /out/outbox /out/state

# -----------------------------------------------------------------------------
# Stage: CI tools (semgrep + betterleaks + trivy - NO nuclei)
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS tools-ci
ARG PIP_VERSION

ARG TARGETARCH
# semgrep and its whole dependency set are pinned in docker/semgrep-constraints.txt
# (bump both together). semgrep 1.93.0 pulled opentelemetry-instrumentation
# 0.46b0, which imports pkg_resources; setuptools >= 81 removed it, so
# `semgrep` died with ModuleNotFoundError in every published image.
ARG SEMGREP_VERSION=1.179.0
# Betterleaks (gitleaks' successor) v1.x: v2 changes the JSON report the
# sensor parses. The archive SHA-256 per architecture is pinned here (from the
# release's checksums.txt, itself signed: checksums.txt.sigstore.json); bump
# all three together.
ARG BETTERLEAKS_VERSION=1.9.0
ARG BETTERLEAKS_SHA256_AMD64=f8b185a39ffcece2a1ca82bf3a4e7435cd81963ffd16b7a9128daf75f35f6de7
ARG BETTERLEAKS_SHA256_ARM64=1d39116e0a58dc94574715e2aa12a2dbd5062f193eee3fec011fef6ba06bd13b
ARG TRIVY_VERSION=0.75.0

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep against the pinned dependency set, then prove it runs: a
# broken install fails the build instead of shipping an image whose sensor
# silently skips semgrep.
COPY docker/semgrep-constraints.txt /tmp/semgrep-constraints.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "pip==${PIP_VERSION}" \
    && pip install --constraint /tmp/semgrep-constraints.txt "semgrep==${SEMGREP_VERSION}" \
    && semgrep --version

# Download betterleaks and trivy with SHA-256 verification.
#
# Supply-chain defence (audit Pass-2 finding): `curl … | tar -xz`
# without checksum check is trust-on-TLS only. If the GitHub CDN or
# a BGP-hijacked route returns a tampered archive, we would install
# a backdoored betterleaks/trivy binary and every scan run by the sensor
# would execute attacker code under scanner privileges.
#
# betterleaks: the archive's SHA-256 is pinned in the ARGs above, so a
# tampered release asset fails even if the checksums file is tampered too.
# trivy: its release publishes `trivy_<v>_checksums.txt`; we download the
# archive and the checksums file separately, verify the SHA-256 of the
# archive against it, and only then extract. A tampered archive fails
# sha256sum -c and `set -eux` aborts the build.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64) BETTERLEAKS_ARCH="x64"; BETTERLEAKS_SHA256="${BETTERLEAKS_SHA256_AMD64}"; TRIVY_ARCH="64bit" ;; \
    arm64) BETTERLEAKS_ARCH="arm64"; BETTERLEAKS_SHA256="${BETTERLEAKS_SHA256_ARM64}"; TRIVY_ARCH="ARM64" ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    # --- betterleaks ---
    BETTERLEAKS_ARCHIVE="betterleaks_${BETTERLEAKS_VERSION}_linux_${BETTERLEAKS_ARCH}.tar.gz"; \
    curl -fsSL -o "${BETTERLEAKS_ARCHIVE}" \
        "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/${BETTERLEAKS_ARCHIVE}"; \
    echo "${BETTERLEAKS_SHA256}  ${BETTERLEAKS_ARCHIVE}" | sha256sum -c -; \
    tar -xzf "${BETTERLEAKS_ARCHIVE}" -C /usr/local/bin betterleaks; \
    # --- trivy ---
    TRIVY_ARCHIVE="trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
    curl -fsSL -o "${TRIVY_ARCHIVE}" \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_ARCHIVE}"; \
    curl -fsSL -o trivy-checksums.txt \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " ${TRIVY_ARCHIVE}\$" trivy-checksums.txt | sha256sum -c -; \
    tar -xzf "${TRIVY_ARCHIVE}" -C /usr/local/bin trivy; \
    chmod +x /usr/local/bin/betterleaks /usr/local/bin/trivy; \
    # Leave /tmp clean so the final image doesn't carry the archives
    rm -f "${BETTERLEAKS_ARCHIVE}" "${TRIVY_ARCHIVE}" trivy-checksums.txt

# -----------------------------------------------------------------------------
# Stage: All tools (CI tools + nuclei - for full/platform images)
# -----------------------------------------------------------------------------
FROM tools-ci AS tools-all

ARG TARGETARCH
ARG NUCLEI_VERSION=3.11.1

# nuclei install with SHA-256 verification — same rationale as betterleaks/trivy above.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH}" in \
    amd64) NUCLEI_ARCH="amd64" ;; \
    arm64) NUCLEI_ARCH="arm64" ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    NUCLEI_ARCHIVE="nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"; \
    curl -fsSL -o "${NUCLEI_ARCHIVE}" \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${NUCLEI_ARCHIVE}"; \
    curl -fsSL -o nuclei-checksums.txt \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep " ${NUCLEI_ARCHIVE}\$" nuclei-checksums.txt | sha256sum -c -; \
    unzip -o "${NUCLEI_ARCHIVE}" -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm -f "${NUCLEI_ARCHIVE}" nuclei-checksums.txt

# ProjectDiscovery recon tools for EASM discovery (api RFC-036): subfinder,
# dnsx, naabu, httpx, katana. Each archive's SHA-256 is pinned per
# architecture (from the release's checksums file), as for betterleaks: a
# tampered asset fails even if the checksums file is tampered too. Bump a
# version and its two hashes together, and the help file the SDK checks the
# tool's flags against (internal/recon/testdata/<tool>-<v>.help).
# naabu runs as a TCP connect scan (the sensor pins it), so the image needs
# neither libpcap nor CAP_NET_RAW, and stays non-root.
ARG SUBFINDER_VERSION=2.16.0
ARG SUBFINDER_SHA256_AMD64=1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60
ARG SUBFINDER_SHA256_ARM64=c81d49559c0f630177be9e347e502e7a3d474aacc6ff78291ffcb4964367d63d
ARG DNSX_VERSION=1.3.1
ARG DNSX_SHA256_AMD64=438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533
ARG DNSX_SHA256_ARM64=dd657dd1ccee5e137eca2dbad0e97dbd067555f744adb97efcda774f1b2fbde1
ARG NAABU_VERSION=2.6.1
ARG NAABU_SHA256_AMD64=018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90
ARG NAABU_SHA256_ARM64=3adc2bb2395c3efff89623499b20eea66ef54924c485d3ae86762393a31736ea
ARG HTTPX_VERSION=1.12.0
ARG HTTPX_SHA256_AMD64=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG HTTPX_SHA256_ARM64=fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e
ARG KATANA_VERSION=1.7.0
ARG KATANA_SHA256_AMD64=fe1142d92f418549338ea46d67a472124878482e225d279e9a42700c75d76a4d
ARG KATANA_SHA256_ARM64=9a6885fe9fda850129b110e0f079d42529b0693dd81b59c316f04084935300f0

# Each tool must answer -version, or the build fails: the sensor advertises
# only the tools that answer, so a broken binary would silently drop recon.
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64|arm64) ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    ARCH_UPPER="$(echo "${TARGETARCH}" | tr '[:lower:]' '[:upper:]')"; \
    cd /tmp; \
    for spec in "subfinder:${SUBFINDER_VERSION}" "dnsx:${DNSX_VERSION}" "naabu:${NAABU_VERSION}" \
                "httpx:${HTTPX_VERSION}" "katana:${KATANA_VERSION}"; do \
        tool="${spec%%:*}"; version="${spec#*:}"; \
        sha_var="$(echo "${tool}" | tr '[:lower:]' '[:upper:]')_SHA256_${ARCH_UPPER}"; \
        sha="${!sha_var}"; \
        archive="${tool}_${version}_linux_${TARGETARCH}.zip"; \
        curl -fsSL -o "${archive}" \
            "https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${archive}"; \
        echo "${sha}  ${archive}" | sha256sum -c -; \
        unzip -o "${archive}" "${tool}" -d /usr/local/bin; \
        chmod 0755 "/usr/local/bin/${tool}"; \
        rm -f "${archive}"; \
        HOME=/tmp/pd-check "/usr/local/bin/${tool}" -version -duc </dev/null; \
    done; \
    rm -rf /tmp/pd-check

# -----------------------------------------------------------------------------
# Stage: nuclei-templates, pinned and gated (scripts/nuclei-templates-bake.sh)
# -----------------------------------------------------------------------------
# The release is pinned with the SHA-256 of its archive (the release's
# nuclei-templates-<v>_checksums.txt lists it); bump both together, and only
# to a release the pinned nuclei validates: the bake script fails the build
# for any template that fails `nuclei -validate` and is not in
# docker/nuclei-templates-allowlist.txt, for a scan run that logs an error,
# and for a release whose .nuclei-ignore stops excluding dos / fuzz /
# bruteforce / local / txt-service. It also writes nuclei's configuration for
# the set ($HOME/.config/nuclei: templates directory and release, the
# release's exclusion list) and the release record the sensor reports
# (openctem-templates-release.json). Templates are arch-independent; nuclei
# runs natively here (CI builds each arch on its own runner).
FROM tools-all AS nuclei-templates
ARG NUCLEI_TEMPLATES_VERSION=10.4.9
ARG NUCLEI_TEMPLATES_SHA256=d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6
COPY scripts/nuclei-templates-bake.sh /tmp/nuclei-templates-bake.sh
COPY docker/nuclei-templates-allowlist.txt /tmp/nuclei-templates-allowlist.txt
# The runtime user's home: nuclei records the templates directory's absolute path.
ENV HOME=/home/openctem
RUN bash /tmp/nuclei-templates-bake.sh "${NUCLEI_TEMPLATES_VERSION}" "${NUCLEI_TEMPLATES_SHA256}" /tmp/nuclei-templates-allowlist.txt

# =============================================================================
# TARGETS
# =============================================================================

# -----------------------------------------------------------------------------
# Target: SLIM (distroless, no tools)
# Use case: Custom tool integration, minimal footprint
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS slim

LABEL org.opencontainers.image.title="OpenCTEM Sensor Slim"
LABEL org.opencontainers.image.description="Minimal security scanning sensor (distroless)"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"

COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# The daemon's outbox (undelivered results). Mount a persistent volume here.
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/outbox /var/lib/openctem/outbox
# The sensor's state (the API key it renews on its own, api RFC-032 Phase 0).
# Mount a persistent volume here; it is deliberately not a VOLUME: an
# anonymous volume is lost with the container, and the sensor renews its key
# automatically only when this directory is a real mount.
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/state /var/lib/openctem/state
VOLUME ["/var/lib/openctem/outbox"]

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: FULL (all tools including nuclei, non-root)
# Use case: Local development, manual testing
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS full

LABEL org.opencontainers.image.title="OpenCTEM Sensor"
LABEL org.opencontainers.image.description="Security scanning sensor with all tools"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r openctem && useradd -r -g openctem -d /home/openctem -m openctem

# Copy all tools including nuclei
COPY --from=tools-all /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-all /usr/local/bin/*semgrep* /usr/local/bin/
COPY --from=tools-all /usr/local/bin/betterleaks /usr/local/bin/
COPY --from=tools-all /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools-all /usr/local/bin/nuclei /usr/local/bin/
# Recon tools (EASM discovery)
COPY --from=tools-all /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/naabu /usr/local/bin/httpx /usr/local/bin/katana /usr/local/bin/

COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# No package installer in the runtime image: pip (and ensurepip's bundled
# wheel, which would bring it back) is deleted. semgrep needs its
# site-packages, not pip. apt/dpkg stay: Debian's base cannot run without dpkg.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.12/ensurepip \
        /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
    && ! python3 -m pip --version >/dev/null 2>&1

RUN mkdir -p /scan /config /cache /home/openctem/.config /var/lib/openctem/outbox /var/lib/openctem/content /var/lib/openctem/state \
    && chown -R openctem:openctem /scan /config /cache /home/openctem/.config /var/lib/openctem \
    && chmod 0700 /var/lib/openctem/outbox /var/lib/openctem/state

# The pinned, gated nuclei-templates release (stage nuclei-templates). The
# templates are root-owned and read-only to the sensor; nuclei's
# configuration directory is the sensor's (nuclei writes its config there).
# The sensor adopts the set as its first managed version
# (internal/content, baked import) and reports its release and digest.
COPY --from=nuclei-templates /home/openctem/nuclei-templates /home/openctem/nuclei-templates
COPY --from=nuclei-templates --chown=openctem:openctem /home/openctem/.config/nuclei /home/openctem/.config/nuclei

ENV HOME=/home/openctem
ENV TRIVY_CACHE_DIR=/cache/trivy
# Managed scanner content (trivy DB, nuclei templates, semgrep rules): the
# daemon refreshes, verifies and swaps it here. Mount a volume to keep it
# across container restarts (the trivy DB alone is ~1.5 GB per version).
ENV SENSOR_CONTENT_DIR=/var/lib/openctem/content

# The daemon's outbox: results not yet accepted by the platform. Mount a
# persistent volume here so a restart or re-created container loses nothing.
# The content cache is a volume too, so a restart does not download it again.
# /var/lib/openctem/state (the renewed API key) is deliberately not a VOLUME:
# mount a named volume or a PVC there; an anonymous volume is lost with the
# container, and the sensor renews its key automatically only when the
# directory is a real mount (api RFC-032 Phase 0).
VOLUME ["/var/lib/openctem/outbox", "/var/lib/openctem/content"]

USER openctem
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: PLATFORM (published as the "-default" image)
# Use case: a long-running sensor the platform dispatches scans to
# (server-controlled daemon), with every tool
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS platform

LABEL org.opencontainers.image.title="OpenCTEM Platform Sensor"
LABEL org.opencontainers.image.description="Platform-managed security scanning sensor"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for platform sensor
RUN groupadd -r openctem && useradd -r -g openctem -d /home/openctem -m openctem

# nuclei and the recon tools. The CI tools (semgrep, betterleaks, trivy) are
# not in the daemon image: CI scanning is openctemio/ci; a daemon that must
# run them uses the per-tool image (Dockerfile.semgrep, .trivy, .betterleaks).
COPY --from=tools-all /usr/local/bin/nuclei /usr/local/bin/
# Recon tools (EASM discovery)
COPY --from=tools-all /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/naabu /usr/local/bin/httpx /usr/local/bin/katana /usr/local/bin/

COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create directories for platform sensor
RUN mkdir -p /scan /config /cache /home/openctem/.openctem /home/openctem/.config /var/lib/openctem/outbox /var/lib/openctem/content /var/lib/openctem/state \
    && chown -R openctem:openctem /scan /config /cache /home/openctem /var/lib/openctem \
    && chmod 0700 /var/lib/openctem/outbox /var/lib/openctem/state

# The pinned, gated nuclei-templates release (stage nuclei-templates). The
# templates are root-owned and read-only to the sensor; nuclei's
# configuration directory is the sensor's (nuclei writes its config there).
# The sensor adopts the set as its first managed version
# (internal/content, baked import) and reports its release and digest.
COPY --from=nuclei-templates /home/openctem/nuclei-templates /home/openctem/nuclei-templates
COPY --from=nuclei-templates --chown=openctem:openctem /home/openctem/.config/nuclei /home/openctem/.config/nuclei

# No package installer in the runtime image: pip (and ensurepip's bundled
# wheel, which would bring it back) is deleted. apt/dpkg stay: Debian's base
# cannot run without dpkg.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.12/ensurepip \
        /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
    && ! python3 -m pip --version >/dev/null 2>&1

ENV HOME=/home/openctem
# Managed scanner content (nuclei templates): the
# daemon refreshes, verifies and swaps it here. Mount a volume to keep it
# across container restarts (the trivy DB alone is ~1.5 GB per version).
ENV SENSOR_CONTENT_DIR=/var/lib/openctem/content
# The daemon runs every scanner installed in this image (nuclei and the
# recon tools subfinder, dnsx, naabu, httpx, katana) and reports them to the platform on its heartbeat; nothing
# is declared on the platform. -e SENSOR_TOOLS=... (or
# -tools) is an optional allowlist that narrows them.

# The daemon's outbox: results not yet accepted by the platform. Mount a
# persistent volume here so a restart or re-created container loses nothing.
# The content cache is a volume too, so a restart does not download it again.
# /var/lib/openctem/state (the renewed API key) is deliberately not a VOLUME:
# mount a named volume or a PVC there; an anonymous volume is lost with the
# container, and the sensor renews its key automatically only when the
# directory is a real mount (api RFC-032 Phase 0).
VOLUME ["/var/lib/openctem/outbox", "/var/lib/openctem/content"]

USER openctem
WORKDIR /scan

# Default: the server-controlled daemon. It needs API_URL and API_KEY
# (-e API_URL=... -e API_KEY=...) and says so if they are missing. The old
# default, -platform, speaks /api/v1/platform/register|lease|poll, which the
# API does not serve, so the image could never connect as shipped.
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["-daemon", "-enable-commands", "-verbose"]
