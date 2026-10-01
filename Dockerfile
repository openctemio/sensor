# syntax=docker/dockerfile:1.7
# =============================================================================
# OpenCTEM Sensor - Main Dockerfile
# =============================================================================
# This file contains:
#   - Builder stages (shared by all images)
#   - Combined images (slim, full, ci, platform)
#
# For per-tool images, see:
#   - Dockerfile.semgrep  (SAST)
#   - Dockerfile.betterleaks (Secrets)
#   - Dockerfile.trivy    (SCA/IaC/Container)
#   - Dockerfile.nuclei   (DAST - NOT for CI, separate workflow)
#
# Docker Image Strategy:
#   - CI images: semgrep + betterleaks + trivy (no nuclei)
#   - DAST images: nuclei only (separate deployment/staging workflow)
#   - Full images: all tools (local development, platform sensors)
#
# Build examples:
#   docker build --target slim -t openctemio/sensor:slim .
#   docker build --target ci -t openctemio/sensor:ci .
#   docker build --target full -t openctemio/sensor:full .
#   docker build --target platform -t openctemio/sensor:platform .
#
# =============================================================================

# -----------------------------------------------------------------------------
# Stage: Build Go binary (standalone - for public distribution)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26-alpine AS builder

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY . /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

# Build standalone sensor (no platform mode)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/openctemio-sensor \
    . \
    && mkdir -p /out/outbox

# -----------------------------------------------------------------------------
# Stage: Build Go binary (platform - for internal use)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26-alpine AS builder-platform

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY . /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

# Build platform sensor (with platform mode)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags platform -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/openctemio-sensor \
    .

# -----------------------------------------------------------------------------
# Stage: CI tools (semgrep + betterleaks + trivy - NO nuclei)
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS tools-ci

ARG TARGETARCH
# semgrep and its whole dependency set are pinned in docker/semgrep-constraints.txt
# (bump both together). semgrep 1.93.0 pulled opentelemetry-instrumentation
# 0.46b0, which imports pkg_resources; setuptools >= 81 removed it, so
# `semgrep` died with ModuleNotFoundError in every published image.
ARG SEMGREP_VERSION=1.178.0
# Betterleaks (gitleaks' successor) v1.x: v2 changes the JSON report the
# sensor parses. The archive SHA-256 per architecture is pinned here (from the
# release's checksums.txt, itself signed: checksums.txt.sigstore.json); bump
# all three together.
ARG BETTERLEAKS_VERSION=1.9.0
ARG BETTERLEAKS_SHA256_AMD64=f8b185a39ffcece2a1ca82bf3a4e7435cd81963ffd16b7a9128daf75f35f6de7
ARG BETTERLEAKS_SHA256_ARM64=1d39116e0a58dc94574715e2aa12a2dbd5062f193eee3fec011fef6ba06bd13b
ARG TRIVY_VERSION=0.69.3

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep against the pinned dependency set, then prove it runs: a
# broken install fails the build instead of shipping an image whose sensor
# silently skips semgrep.
COPY docker/semgrep-constraints.txt /tmp/semgrep-constraints.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --constraint /tmp/semgrep-constraints.txt "semgrep==${SEMGREP_VERSION}" \
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
ARG NUCLEI_VERSION=3.4.1

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

# =============================================================================
# TARGETS
# =============================================================================

# -----------------------------------------------------------------------------
# Target: SLIM (distroless, no tools)
# Use case: Custom tool integration, minimal footprint
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS slim

LABEL org.opencontainers.image.title="OpenCTEM Sensor Slim"
LABEL org.opencontainers.image.description="Minimal security scanning sensor (distroless)"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"

COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# The daemon's outbox (undelivered results). Mount a persistent volume here.
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/outbox /var/lib/openctem/outbox
VOLUME ["/var/lib/openctem/outbox"]

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: CI (SAST + Secrets + SCA - NO DAST)
# Use case: PR/MR security checks, CI pipelines
# Tools: semgrep, betterleaks, trivy
#
# NOTE: Trivy DB is NOT preloaded to ensure fresh vulnerabilities.
# The first scan will download the latest DB (~40MB, cached after).
# For faster CI, use weekly rebuilt images or mount DB cache volume.
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS ci

LABEL org.opencontainers.image.title="OpenCTEM Sensor CI"
LABEL org.opencontainers.image.description="CI-optimized security scanning (SAST + Secrets + SCA)"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Copy CI tools only (no nuclei)
COPY --from=tools-ci /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-ci /usr/local/bin/*semgrep* /usr/local/bin/
COPY --from=tools-ci /usr/local/bin/betterleaks /usr/local/bin/
COPY --from=tools-ci /usr/local/bin/trivy /usr/local/bin/

COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Trivy cache directory - DB will be downloaded on first use
ENV TRIVY_CACHE_DIR=/root/.cache/trivy
ENV TRIVY_NO_PROGRESS=true
ENV CI=true

# Avoid "dubious ownership" in GitHub Actions workspace
RUN git config --global --add safe.directory '*'

WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: CI-CACHED (CI + preloaded Trivy DB)
# Use case: Faster CI when you rebuild images weekly
# WARNING: DB becomes stale! Rebuild images at least weekly.
# -----------------------------------------------------------------------------
FROM ci AS ci-cached

LABEL org.opencontainers.image.title="OpenCTEM Sensor CI (Cached DB)"
LABEL org.opencontainers.image.description="CI sensor with preloaded Trivy DB - rebuild weekly!"

# Preload Trivy vulnerability DB
RUN trivy image --download-db-only --no-progress

# -----------------------------------------------------------------------------
# Target: FULL (all tools including nuclei, non-root)
# Use case: Local development, manual testing
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS full

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

COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

RUN mkdir -p /scan /config /cache /var/lib/openctem/outbox \
    && chown -R openctem:openctem /scan /config /cache /var/lib/openctem \
    && chmod 0700 /var/lib/openctem/outbox

ENV HOME=/home/openctem
ENV TRIVY_CACHE_DIR=/cache/trivy

# The daemon's outbox: results not yet accepted by the platform. Mount a
# persistent volume here so a restart or re-created container loses nothing.
VOLUME ["/var/lib/openctem/outbox"]

USER openctem
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: PLATFORM (published as the "-default" image)
# Use case: a long-running sensor the platform dispatches scans to
# (server-controlled daemon), with every tool
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS platform

LABEL org.opencontainers.image.title="OpenCTEM Platform Sensor"
LABEL org.opencontainers.image.description="Platform-managed security scanning sensor"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for platform sensor
RUN groupadd -r openctem && useradd -r -g openctem -d /home/openctem -m openctem

# Copy all tools including nuclei
COPY --from=tools-all /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-all /usr/local/bin/*semgrep* /usr/local/bin/
COPY --from=tools-all /usr/local/bin/betterleaks /usr/local/bin/
COPY --from=tools-all /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools-all /usr/local/bin/nuclei /usr/local/bin/

# Use builder-platform for platform sensor binary (with -tags platform)
COPY --from=builder-platform /out/openctemio-sensor /usr/local/bin/openctemio-sensor
COPY --from=builder-platform /usr/share/zoneinfo /usr/share/zoneinfo

# Create directories for platform sensor
RUN mkdir -p /scan /config /cache /home/openctem/.openctem /var/lib/openctem/outbox \
    && chown -R openctem:openctem /scan /config /cache /home/openctem /var/lib/openctem \
    && chmod 0700 /var/lib/openctem/outbox

ENV HOME=/home/openctem
ENV TRIVY_CACHE_DIR=/cache/trivy
# The scanners this image's daemon runs for the platform (override with
# -e SENSOR_TOOLS=... or -tools).
ENV SENSOR_TOOLS=semgrep,betterleaks,trivy,nuclei

# The daemon's outbox: results not yet accepted by the platform. Mount a
# persistent volume here so a restart or re-created container loses nothing.
VOLUME ["/var/lib/openctem/outbox"]

USER openctem
WORKDIR /scan

# Default: the server-controlled daemon. It needs API_URL and API_KEY
# (-e API_URL=... -e API_KEY=...) and says so if they are missing. The old
# default, -platform, speaks /api/v1/platform/register|lease|poll, which the
# API does not serve, so the image could never connect as shipped.
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["-daemon", "-enable-commands", "-verbose"]
