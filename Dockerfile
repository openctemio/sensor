# syntax=docker/dockerfile:1.7
# =============================================================================
# OpenCTEM Sensor - Main Dockerfile
# =============================================================================
# This file contains:
#   - Builder stages (shared by all images)
#   - Combined images (slim, passive, full, platform)
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
#   - Sensor profiles (docs/PROFILES.md), one per intrusiveness ceiling:
#       passive  : passive discovery only (subfinder; rdap and asn are
#                  compiled in). No program that can send a packet to a
#                  target is in the image: the smoke test refuses the image
#                  if the binary of any active tool (tier above T0) is there.
#       standard : the platform (default) image: the daemon with nuclei and
#                  the recon tools subfinder, dnsx, naabu, httpx and katana;
#                  no CI tools. Published as -default, -standard and plain.
#       full     : every tool, the code scanners included.
#   - Per-tool images (semgrep, trivy, betterleaks, nuclei): one tool, one-shot
#     by default (they set CI=true); -e CI=false runs one as the daemon.
#
# Build examples:
#   docker build --target slim -t openctemio/sensor:slim .
#   docker build --target full -t openctemio/sensor:full .
#   docker build --target passive -t openctemio/sensor:passive .
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
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS builder

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
    && mkdir -p /out/data/outbox /out/data/state /out/data/content /out/data/store /out/data/workspaces \
    && chmod 0755 /out/data && chmod 0700 /out/data/outbox /out/data/state /out/data/store /out/data/workspaces

# -----------------------------------------------------------------------------
# Stage: CI tools (semgrep + betterleaks + trivy - NO nuclei)
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS tools-ci
ARG PIP_VERSION

ARG TARGETARCH
# semgrep and its whole dependency set are hash-locked in docker/semgrep-requirements.txt
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
ARG TRIVY_VERSION=0.76.0
# trivy's archive SHA-256 per architecture (from the release's
# trivy_<v>_checksums.txt); bump all three together, here and in
# Dockerfile.trivy.
ARG TRIVY_SHA256_AMD64=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7
ARG TRIVY_SHA256_ARM64=aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep against the pinned dependency set, then prove it runs: a
# broken install fails the build instead of shipping an image whose sensor
# silently skips semgrep.
COPY docker/pip-requirements.txt docker/semgrep-requirements.txt /tmp/
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --require-hashes --no-deps -r /tmp/pip-requirements.txt \
    && pip --version | grep -q "^pip ${PIP_VERSION} " \
    && pip install --require-hashes --no-deps -r /tmp/semgrep-requirements.txt \
    && semgrep --version | grep -qx "${SEMGREP_VERSION}" \
    && rm -f /tmp/pip-requirements.txt /tmp/semgrep-requirements.txt

# Download betterleaks and trivy with SHA-256 verification.
#
# Supply-chain defence (audit Pass-2 finding): `curl … | tar -xz`
# without checksum check is trust-on-TLS only. If the GitHub CDN or
# a BGP-hijacked route returns a tampered archive, we would install
# a backdoored betterleaks/trivy binary and every scan run by the sensor
# would execute attacker code under scanner privileges.
#
# Each archive's SHA-256 is pinned in the ARGs above (taken from the
# release's checksums file when the version is bumped), so a tampered or
# replaced release asset fails sha256sum -c even if the release's checksums
# file was replaced with it, and `set -eux` aborts the build.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    case "${TARGETARCH}" in \
    amd64) BETTERLEAKS_ARCH="x64"; BETTERLEAKS_SHA256="${BETTERLEAKS_SHA256_AMD64}"; TRIVY_ARCH="64bit"; TRIVY_SHA256="${TRIVY_SHA256_AMD64}" ;; \
    arm64) BETTERLEAKS_ARCH="arm64"; BETTERLEAKS_SHA256="${BETTERLEAKS_SHA256_ARM64}"; TRIVY_ARCH="ARM64"; TRIVY_SHA256="${TRIVY_SHA256_ARM64}" ;; \
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
    echo "${TRIVY_SHA256}  ${TRIVY_ARCHIVE}" | sha256sum -c -; \
    tar -xzf "${TRIVY_ARCHIVE}" -C /usr/local/bin trivy; \
    chmod +x /usr/local/bin/betterleaks /usr/local/bin/trivy; \
    # Leave /tmp clean so the final image doesn't carry the archives
    rm -f "${BETTERLEAKS_ARCHIVE}" "${TRIVY_ARCHIVE}"

# Stage: recon-build - nuclei + recon tools from source (api RFC-036)
# -----------------------------------------------------------------------------
# Built with the pinned Go toolchain (the same golang image the API uses), so
# every tool carries its standard library fixes; scripts/build-pd-tool.sh also
# raises the Go modules the pinned releases still carry vulnerable. Each tag is
# pinned by its commit SHA (the build fails if the tag moves), as the release
# archives were pinned by SHA-256. Bump a version and its commit together
# (`git ls-remote https://github.com/projectdiscovery/<tool> refs/tags/v<ver>`),
# here and in Dockerfile.nuclei, and the help file the SDK checks the tool's
# flags against (internal/recon/testdata/<tool>-<v>.help). Static binaries, no
# cgo: the same target architecture as the runtime stage (CI builds each
# architecture on its own runner).
FROM public.ecr.aws/docker/library/golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS recon-build
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_COMMIT=a8c88feb4a1c8e961b7902534ce3af97e9d524a4
ARG SUBFINDER_VERSION=2.17.0
ARG SUBFINDER_COMMIT=c97f25802892093060f0fc424bfc3f39e273693a
ARG DNSX_VERSION=1.3.1
ARG DNSX_COMMIT=01e315f216db7d36198ec326fac13dd7846b1bec
ARG NAABU_VERSION=2.6.1
ARG NAABU_COMMIT=5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8
ARG HTTPX_VERSION=1.12.0
ARG HTTPX_COMMIT=4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8
ARG KATANA_VERSION=1.8.0
ARG KATANA_COMMIT=35267ac5c8ff1db9694a319d0eb466ed97b0969f

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates
COPY scripts/build-pd-tool.sh /usr/local/bin/build-pd-tool.sh
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    mkdir -p /out; \
    build-pd-tool.sh nuclei "${NUCLEI_VERSION}" "${NUCLEI_COMMIT}" /out; \
    build-pd-tool.sh subfinder "${SUBFINDER_VERSION}" "${SUBFINDER_COMMIT}" /out; \
    build-pd-tool.sh dnsx "${DNSX_VERSION}" "${DNSX_COMMIT}" /out; \
    build-pd-tool.sh naabu "${NAABU_VERSION}" "${NAABU_COMMIT}" /out; \
    build-pd-tool.sh httpx "${HTTPX_VERSION}" "${HTTPX_COMMIT}" /out; \
    build-pd-tool.sh katana "${KATANA_VERSION}" "${KATANA_COMMIT}" /out

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Stage: nuclei + the recon tools (platform image; the full image adds them to
# the CI tools). Independent of tools-ci, so the platform image does not
# install semgrep, betterleaks or trivy just to discard them.
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS tools-recon

# nuclei and the ProjectDiscovery recon tools (subfinder, dnsx, naabu, httpx,
# katana) are built from source in stage recon-build below, not downloaded:
# the upstream release binaries embed the Go standard library and module
# versions of the day they were cut, which lag behind security fixes.
# naabu runs as a TCP connect scan (the sensor pins it), so the image needs
# neither libpcap nor CAP_NET_RAW, and stays non-root.
COPY --from=recon-build /out/ /usr/local/bin/

# curl and ca-certificates: the nuclei-templates stage below downloads the
# pinned templates release from this stage.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Each tool must answer -version, or the build fails: the sensor advertises
# only the tools that answer, so a broken binary would silently drop recon.
RUN set -eux; \
    for tool in nuclei subfinder dnsx naabu httpx katana; do \
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
FROM tools-recon AS nuclei-templates
ARG NUCLEI_TEMPLATES_VERSION=10.4.9
ARG NUCLEI_TEMPLATES_SHA256=d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6
COPY scripts/nuclei-templates-bake.sh /tmp/nuclei-templates-bake.sh
COPY docker/nuclei-templates-allowlist.txt /tmp/nuclei-templates-allowlist.txt
# The runtime user's home: nuclei records the templates directory's absolute path.
ENV HOME=/home/openctem
RUN bash /tmp/nuclei-templates-bake.sh "${NUCLEI_TEMPLATES_VERSION}" "${NUCLEI_TEMPLATES_SHA256}" /tmp/nuclei-templates-allowlist.txt

# -----------------------------------------------------------------------------
# Stage: All tools (CI tools + nuclei and the recon tools - full image)
# -----------------------------------------------------------------------------
FROM tools-ci AS tools-all
COPY --from=tools-recon /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/naabu /usr/local/bin/httpx /usr/local/bin/katana /usr/local/bin/

# -----------------------------------------------------------------------------
# Stage: the platform image's root filesystem additions, owned by the runtime
# user (uid/gid 999, the uid the image has always run as, so the data volumes
# of existing sensors stay readable): its passwd/group entries on top of the
# distroless ones, its home, and the working directories.
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:8c563c1fb5e120606f0d85733049775faed6192e2bd2223ef283a5393eec22b9 AS platform-base

FROM builder AS platform-fs
COPY --from=platform-base /etc/passwd /etc/group /out/etc/
RUN echo 'openctem:x:999:999:openctem:/home/openctem:/sbin/nologin' >> /out/etc/passwd \
    && echo 'openctem:x:999:' >> /out/etc/group \
    && mkdir -p /out/home/openctem/.openctem /out/home/openctem/.config /out/scan /out/config /out/cache \
    && chmod 0700 /out/home/openctem

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
# The sensor's data directory: state/ (the paired identity or the API key it
# renews, api RFC-032 Phase 0), outbox/ (undelivered results) and content/.
# Mount ONE persistent volume at /var/lib/openctem (a volume on each
# subdirectory works too). Deliberately no VOLUME: an anonymous volume looks
# like a real mount to the sensor's persistence check and is lost with a new
# container, and a VOLUME on a subdirectory would shadow that subdirectory
# of a volume mounted at /var/lib/openctem.
COPY --from=builder --chown=65532:65532 /out/data /var/lib/openctem

WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: FULL (all tools including nuclei, non-root)
# Use case: Local development, manual testing
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS full

LABEL org.opencontainers.image.title="OpenCTEM Sensor"
LABEL org.opencontainers.image.description="Security scanning sensor with all tools"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"
LABEL io.openctem.sensor.profile="full"

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

RUN mkdir -p /scan /config /cache /home/openctem/.config /var/lib/openctem/outbox /var/lib/openctem/content /var/lib/openctem/state /var/lib/openctem/store /var/lib/openctem/workspaces \
    && chown -R openctem:openctem /scan /config /cache /home/openctem/.config /var/lib/openctem \
    && chmod 0700 /var/lib/openctem/outbox /var/lib/openctem/state /var/lib/openctem/store /var/lib/openctem/workspaces

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

# The sensor's data directory /var/lib/openctem holds store/ (the encrypted
# local store: keys of the sealed outbox items, job journal; same volume as
# outbox/; SENSOR_STORE_KEY_FILE may point at a mounted secret; no key is ever
# baked into the image), workspaces/ (per-job scratch) and state/ (the paired
# identity or the renewed API key), outbox/ (results not yet accepted by the
# platform) and content/ (the cache above). Mount ONE persistent volume at
# /var/lib/openctem so a re-created container keeps its identity and loses
# no results (a volume on each subdirectory works too). Deliberately no
# VOLUME: an anonymous volume looks like a real mount to the sensor's
# persistence check and is lost with a new container, and a VOLUME on a
# subdirectory would shadow that subdirectory of a volume mounted at
# /var/lib/openctem (api RFC-032 Phase 0).

USER openctem
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["--help"]

# -----------------------------------------------------------------------------
# Target: PASSIVE (published as the "-passive" image)
# Use case: a sensor that must never touch a target: passive discovery from
# third-party sources (subfinder) and the compiled-in registration and
# network lookups (rdap, asn). Same layout, user and data directory as the
# platform image below, so moving a sensor between profiles keeps its volume.
# -----------------------------------------------------------------------------
# Only T0 (passive) tools whose every program is passive are here: dnsx is
# not, because dnsx-enum (enumerate.subdomains, T1) runs the same binary. The
# smoke test (scripts/image-smoke-test.sh) derives the forbidden binaries
# from the compiled-in tool manifests and fails the build if one is present.
FROM platform-base AS passive

LABEL org.opencontainers.image.title="OpenCTEM Sensor (passive)"
LABEL org.opencontainers.image.description="Passive discovery sensor: no program that touches a target"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"
LABEL io.openctem.sensor.profile="passive"

COPY --from=platform-fs /out/etc/passwd /out/etc/group /etc/
COPY --from=platform-fs --chown=999:999 /out/home/openctem /home/openctem
COPY --from=platform-fs --chown=999:999 /out/scan /scan
COPY --from=platform-fs --chown=999:999 /out/config /config
COPY --from=platform-fs --chown=999:999 /out/cache /cache
COPY --from=builder --chown=999:999 /out/data /var/lib/openctem

COPY --from=tools-recon /usr/local/bin/subfinder /usr/local/bin/
COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor

ENV HOME=/home/openctem
ENV SENSOR_CONTENT_DIR=/var/lib/openctem/content

USER 999:999
WORKDIR /scan

ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["-verbose"]

# -----------------------------------------------------------------------------
# Target: PLATFORM (published as the "-default" image)
# Use case: a long-running sensor the platform dispatches scans to
# (server-controlled daemon), with every tool
# -----------------------------------------------------------------------------
# Distroless (glibc, CA certificates and time zones; no shell, no package
# manager, no Python): the daemon and its tools are the only executables. The
# tools are static Go binaries except naabu, which links glibc.
FROM platform-base AS platform

LABEL org.opencontainers.image.title="OpenCTEM Platform Sensor"
LABEL org.opencontainers.image.description="Platform-managed security scanning sensor"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sensor"
LABEL io.openctem.sensor.profile="standard"

COPY --from=platform-fs /out/etc/passwd /out/etc/group /etc/
COPY --from=platform-fs --chown=999:999 /out/home/openctem /home/openctem
COPY --from=platform-fs --chown=999:999 /out/scan /scan
COPY --from=platform-fs --chown=999:999 /out/config /config
COPY --from=platform-fs --chown=999:999 /out/cache /cache
# The data directory (state/, outbox/, content/, store/, workspaces/; modes set in the builder).
COPY --from=builder --chown=999:999 /out/data /var/lib/openctem

# nuclei and the recon tools. The CI tools (semgrep, betterleaks, trivy) are
# not in the daemon image: CI scanning is openctemio/ci; a daemon that must
# run them uses the per-tool image (Dockerfile.semgrep, .trivy, .betterleaks).
COPY --from=tools-recon /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/naabu /usr/local/bin/httpx /usr/local/bin/katana /usr/local/bin/
COPY --from=builder /out/openctemio-sensor /usr/local/bin/openctemio-sensor

# The pinned, gated nuclei-templates release (stage nuclei-templates). The
# templates are root-owned and read-only to the sensor; nuclei's
# configuration directory is the sensor's (nuclei writes its config there).
# The sensor adopts the set as its first managed version
# (internal/content, baked import) and reports its release and digest.
COPY --from=nuclei-templates /home/openctem/nuclei-templates /home/openctem/nuclei-templates
COPY --from=nuclei-templates --chown=999:999 /home/openctem/.config/nuclei /home/openctem/.config/nuclei

ENV HOME=/home/openctem
# Managed scanner content (nuclei templates): the
# daemon refreshes, verifies and swaps it here. Mount a volume to keep it
# across container restarts (the trivy DB alone is ~1.5 GB per version).
ENV SENSOR_CONTENT_DIR=/var/lib/openctem/content
# The daemon runs every scanner installed in this image (nuclei and the
# recon tools subfinder, dnsx, naabu, httpx, katana; rdap and asn are
# compiled in) whose binary passes its check, and reports them to the
# platform on its heartbeat; nothing is declared on the platform. Narrow
# them with the local policy's tools.allow (SENSOR_TOOLS / -tools still
# narrows for one release, with a deprecation warning).

# The sensor's data directory /var/lib/openctem holds store/ (the encrypted
# local store: keys of the sealed outbox items, job journal; same volume as
# outbox/; SENSOR_STORE_KEY_FILE may point at a mounted secret; no key is ever
# baked into the image), workspaces/ (per-job scratch) and state/ (the paired
# identity or the renewed API key), outbox/ (results not yet accepted by the
# platform) and content/ (the cache above). Mount ONE persistent volume at
# /var/lib/openctem so a re-created container keeps its identity and loses
# no results (a volume on each subdirectory works too). Deliberately no
# VOLUME: an anonymous volume looks like a real mount to the sensor's
# persistence check and is lost with a new container, and a VOLUME on a
# subdirectory would shadow that subdirectory of a volume mounted at
# /var/lib/openctem (api RFC-032 Phase 0).

USER 999:999
WORKDIR /scan

# Default: the daemon with platform commands (the sensor's default mode; no
# -daemon / -enable-commands needed, and a command line that still passes
# them works the same, with a deprecation warning). It needs SENSOR_API_URL
# and says so if it is missing; with SENSOR_PAIRING_CODE (or no key at all)
# it pairs on first start, or it uses SENSOR_API_KEY.
ENTRYPOINT ["/usr/local/bin/openctemio-sensor"]
CMD ["-verbose"]
