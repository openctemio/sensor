#!/usr/bin/env bash
# Print buildx named-context overrides (`<FROM ref>=docker-image://<mirror ref>`)
# that swap each digest-pinned base image of the given Dockerfiles for its copy
# in the public CI image mirror, ghcr.io/openctemio/mirror (maintained by
# openctemio/openctem: .github/ci-images.txt, plus every digest-pinned base of
# this repository's Dockerfiles on main, synced daily).
#
#   scripts/ci-mirror-contexts.sh Dockerfile [Dockerfile...]
#
# Mirrored upstreams:
#   public.ecr.aws/docker/library/<name>  ->  ghcr.io/openctemio/mirror/<name>
#   gcr.io/distroless/<name>              ->  ghcr.io/openctemio/mirror/distroless/<name>
#
# Why: shared GitHub runner IPs exhaust the anonymous public.ecr.aws quota
# ("toomanyrequests: Data limit exceeded", HTTP 429) and the build fails
# before it starts. The override keeps the digest, so the build uses the exact
# same bytes; the Dockerfiles (and Dependabot) keep the upstream references.
# A base whose digest is not in the mirror yet (e.g. just bumped) is left on
# its upstream with a notice, so the build never depends on the mirror.
set -euo pipefail

mirror="${MIRROR_PREFIX:-ghcr.io/openctemio/mirror}"

# Upstream prefix -> path under the mirror. Only these upstreams are swapped.
mirror_ref() {
  case "$1" in
    public.ecr.aws/docker/library/*) echo "$mirror/${1#public.ecr.aws/docker/library/}" ;;
    gcr.io/distroless/*) echo "$mirror/distroless/${1#gcr.io/distroless/}" ;;
    *) return 1 ;;
  esac
}

grep -hoE '^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?[^[:space:]]+@sha256:[0-9a-f]{64}' "$@" \
  | awk '{print $NF}' | sort -u | while read -r ref; do
  target="$(mirror_ref "$ref")" || continue
  ok=0
  for delay in 0 5 15 30; do
    sleep "$delay"
    if docker buildx imagetools inspect "$target" >/dev/null 2>&1; then ok=1; break; fi
  done
  if [ "$ok" -eq 1 ]; then
    echo "$ref=docker-image://$target"
  else
    echo "::notice::$target is not in the CI image mirror; building from $ref" >&2
  fi
done
