#!/usr/bin/env bash
# Pin the CI templates in ci/ to one sensor release, by digest.
#
#   scripts/pin-ci-images.sh v0.9.2
#
# For each image variant the templates use, it resolves the release tag to
# the digest of its multi-platform index, verifies that digest's cosign
# signature (keyless: issued to this repository's docker-publish workflow at
# a v* tag), and rewrites every reference in ci/ to
# ghcr.io/openctemio/sensor:<version>-<variant>@sha256:<digest>.
# A digest that does not verify stops the script before anything is written.
#
# Needs docker (buildx imagetools) and cosign v3 (or docker to run it).
set -euo pipefail

VERSION="${1:?usage: $0 <release tag, e.g. v0.9.2>}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release tag: $VERSION" >&2; exit 2; }
IMAGE=ghcr.io/openctemio/sensor
IDENTITY='^https://github\.com/openctemio/sensor/\.github/workflows/docker-publish\.yml@refs/tags/v'
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cosign_verify() {
  if command -v cosign >/dev/null 2>&1; then
    cosign verify "$1" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "$IDENTITY" >/dev/null
  else
    docker run --rm ghcr.io/sigstore/cosign/cosign:v3.0.6 verify "$1" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "$IDENTITY" >/dev/null
  fi
}

declare -A DIGEST
for variant in ci semgrep betterleaks trivy nuclei; do
  digest="$(docker buildx imagetools inspect "$IMAGE:$VERSION-$variant" --format '{{json .Manifest}}' | jq -r .digest)"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "no index digest for $VERSION-$variant" >&2; exit 1; }
  cosign_verify "$IMAGE@$digest"
  echo "verified $VERSION-$variant $digest"
  DIGEST[$variant]="$digest"
done

# Rewrite "sensor:<anything>-<variant>[@sha256:...]" in the templates.
for f in "$ROOT"/ci/github/*.yml "$ROOT"/ci/gitlab/*.yml; do
  for variant in "${!DIGEST[@]}"; do
    sed -E -i "s#${IMAGE}:[A-Za-z0-9.]+-${variant}(@sha256:[0-9a-f]{64})?#${IMAGE}:${VERSION}-${variant}@${DIGEST[$variant]}#g" "$f"
  done
done
# The composite action's default release.
sed -E -i "/^  version:/,/default:/ s#default: 'v[0-9.]+'#default: '${VERSION}'#" "$ROOT/ci/github/action.yml"
echo "pinned ci/ to $VERSION"
