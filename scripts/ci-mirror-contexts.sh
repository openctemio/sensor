#!/usr/bin/env bash
# Print buildx named-context overrides (`<FROM ref>=docker-image://<mirror ref>`)
# that swap each digest-pinned public.ecr.aws base image of the given
# Dockerfiles for its copy in the public CI image mirror,
# ghcr.io/openctemio/mirror (maintained by openctemio/openctem,
# .github/ci-images.txt).
#
#   scripts/ci-mirror-contexts.sh Dockerfile [Dockerfile...]
#
# Why: shared GitHub runner IPs exhaust the anonymous public.ecr.aws quota
# ("toomanyrequests: Data limit exceeded") and the build fails before it
# starts. The override keeps the digest, so the build uses the exact same
# bytes; the Dockerfiles (and Dependabot) keep the upstream references. A base
# whose digest is not in the mirror (e.g. just bumped) is left on
# public.ecr.aws with a notice, so the build never depends on the mirror.
set -euo pipefail

mirror="${MIRROR_PREFIX:-ghcr.io/openctemio/mirror}"
upstream='public.ecr.aws/docker/library/'

grep -hoE "^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?${upstream//./\\.}[^[:space:]]+@sha256:[0-9a-f]{64}" "$@" \
  | awk '{print $NF}' | sort -u | while read -r ref; do
  target="$mirror/${ref#"$upstream"}"
  ok=0
  for delay in 0 5 15; do
    sleep "$delay"
    if docker buildx imagetools inspect "$target" >/dev/null 2>&1; then ok=1; break; fi
  done
  if [ "$ok" -eq 1 ]; then
    echo "$ref=docker-image://$target"
  else
    echo "::notice::$target is not in the CI image mirror; building from $ref" >&2
  fi
done
