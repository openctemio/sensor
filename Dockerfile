# syntax=docker/dockerfile:1.7
# =============================================================================
# OpenCTEM Agent - Main Dockerfile
# =============================================================================
# This file contains:
#   - Builder stages (shared by all images)
#   - Combined images (slim, full, ci, platform)
#
# For per-tool images, see:
#   - Dockerfile.semgrep  (SAST)
#   - Dockerfile.gitleaks (Secrets)
#   - Dockerfile.trivy    (SCA/IaC/Container)
#   - Dockerfile.nuclei   (DAST - NOT for CI, separate workflow)
#
# Docker Image Strategy:
#   - CI images: semgrep + gitleaks + trivy (no nuclei)
#   - DAST images: nuclei only (separate deployment/staging workflow)
#   - Full images: all tools (local development, platform agents)
#
# Build examples:
#   docker build --target slim -t openctemio/agent:slim .
#   docker build --target ci -t openctemio/agent:ci .
#   docker build --target full -t openctemio/agent:full .
#   docker build --target platform -t openctemio/agent:platform .
#
# =============================================================================

# -----------------------------------------------------------------------------
# Stage: Build Go binary (standalone - for public distribution)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.25-alpine AS builder

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY . /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

# Build standalone agent (no platform mode)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/agent \
    .

# -----------------------------------------------------------------------------
# Stage: Build Go binary (platform - for internal use)
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.25-alpine AS builder-platform

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY . /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

# Build platform agent (with platform mode)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags platform -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /out/agent \
    .

# -----------------------------------------------------------------------------
# Stage: CI tools (semgrep + gitleaks + trivy - NO nuclei)
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS tools-ci

ARG TARGETARCH
ARG SEMGREP_VERSION=1.93.0
ARG GITLEAKS_VERSION=8.30.0
ARG TRIVY_VERSION=0.69.3

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Download gitleaks and trivy
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64) GITLEAKS_ARCH="x64"; TRIVY_ARCH="64bit" ;; \
    arm64) GITLEAKS_ARCH="arm64"; TRIVY_ARCH="ARM64" ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy; \
    chmod +x /usr/local/bin/gitleaks /usr/local/bin/trivy

# -----------------------------------------------------------------------------
# Stage: All tools (CI tools + nuclei - for full/platform images)
# -----------------------------------------------------------------------------
FROM tools-ci AS tools-all

ARG TARGETARCH
ARG NUCLEI_VERSION=3.4.1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH}" in \
    amd64) NUCLEI_ARCH="amd64" ;; \
    arm64) NUCLEI_ARCH="arm64" ;; \
    *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
    -o /tmp/nuclei.zip && unzip /tmp/nuclei.zip -d /usr/local/bin && rm /tmp/nuclei.zip; \
    chmod +x /usr/local/bin/nuclei

# =============================================================================
# TARGETS
# =============================================================================

# -----------------------------------------------------------------------------
# Target: SLIM (distroless, no tools)
# Use case: Custom tool integration, minimal footprint
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS slim

LABEL org.opencontainers.image.title="OpenCTEM Agent Slim"
LABEL org.opencontainers.image.description="Minimal security scanning agent (distroless)"
LABEL org.opencontainers.image.source="https://github.com/openctemio/agent"

COPY --from=builder /out/agent /usr/local/bin/agent
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: CI (SAST + Secrets + SCA - NO DAST)
# Use case: PR/MR security checks, CI pipelines
# Tools: semgrep, gitleaks, trivy
#
# NOTE: Trivy DB is NOT preloaded to ensure fresh vulnerabilities.
# The first scan will download the latest DB (~40MB, cached after).
# For faster CI, use weekly rebuilt images or mount DB cache volume.
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS ci

LABEL org.opencontainers.image.title="OpenCTEM Agent CI"
LABEL org.opencontainers.image.description="CI-optimized security scanning (SAST + Secrets + SCA)"
LABEL org.opencontainers.image.source="https://github.com/openctemio/agent"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Copy CI tools only (no nuclei)
COPY --from=tools-ci /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-ci /usr/local/bin/semgrep /usr/local/bin/pysemgrep /usr/local/bin/
COPY --from=tools-ci /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools-ci /usr/local/bin/trivy /usr/local/bin/

COPY --from=builder /out/agent /usr/local/bin/agent
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Trivy cache directory - DB will be downloaded on first use
ENV TRIVY_CACHE_DIR=/root/.cache/trivy
ENV TRIVY_NO_PROGRESS=true
ENV CI=true

# Avoid "dubious ownership" in GitHub Actions workspace
RUN git config --global --add safe.directory '*'

WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: CI-CACHED (CI + preloaded Trivy DB)
# Use case: Faster CI when you rebuild images weekly
# WARNING: DB becomes stale! Rebuild images at least weekly.
# -----------------------------------------------------------------------------
FROM ci AS ci-cached

LABEL org.opencontainers.image.title="OpenCTEM Agent CI (Cached DB)"
LABEL org.opencontainers.image.description="CI agent with preloaded Trivy DB - rebuild weekly!"

# Preload Trivy vulnerability DB
RUN trivy image --download-db-only --no-progress

# -----------------------------------------------------------------------------
# Target: FULL (all tools including nuclei, non-root)
# Use case: Local development, manual testing
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS full

LABEL org.opencontainers.image.title="OpenCTEM Agent"
LABEL org.opencontainers.image.description="Security scanning agent with all tools"
LABEL org.opencontainers.image.source="https://github.com/openctemio/agent"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r openctem && useradd -r -g openctem -d /home/openctem -m openctem

# Copy all tools including nuclei
COPY --from=tools-all /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-all /usr/local/bin/semgrep /usr/local/bin/pysemgrep /usr/local/bin/
COPY --from=tools-all /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools-all /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools-all /usr/local/bin/nuclei /usr/local/bin/

COPY --from=builder /out/agent /usr/local/bin/agent
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

RUN mkdir -p /scan /config /cache \
    && chown -R openctem:openctem /scan /config /cache

ENV HOME=/home/openctem
ENV TRIVY_CACHE_DIR=/cache/trivy

USER openctem
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: PLATFORM (managed platform agent mode)
# Use case: Platform-managed agents with all capabilities
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim AS platform

LABEL org.opencontainers.image.title="OpenCTEM Platform Agent"
LABEL org.opencontainers.image.description="Platform-managed security scanning agent"
LABEL org.opencontainers.image.source="https://github.com/openctemio/agent"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for platform agent
RUN groupadd -r openctem && useradd -r -g openctem -d /home/openctem -m openctem

# Copy all tools including nuclei
COPY --from=tools-all /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=tools-all /usr/local/bin/semgrep /usr/local/bin/pysemgrep /usr/local/bin/
COPY --from=tools-all /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools-all /usr/local/bin/trivy /usr/local/bin/
COPY --from=tools-all /usr/local/bin/nuclei /usr/local/bin/

# Use builder-platform for platform agent binary (with -tags platform)
COPY --from=builder-platform /out/agent /usr/local/bin/agent
COPY --from=builder-platform /usr/share/zoneinfo /usr/share/zoneinfo

# Create directories for platform agent
RUN mkdir -p /scan /config /cache /home/openctem/.openctem \
    && chown -R openctem:openctem /scan /config /cache /home/openctem

ENV HOME=/home/openctem
ENV TRIVY_CACHE_DIR=/cache/trivy
ENV PLATFORM_MODE=true

USER openctem
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["-platform", "-verbose"]
