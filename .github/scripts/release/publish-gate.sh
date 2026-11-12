#!/usr/bin/env bash
# publish-gate.sh VERSION: publish the GitHub release of VERSION only when
# every image it promises is there.
#
# GoReleaser creates the release as a draft (.goreleaser.yaml). This gate runs
# after every image variant was built, signed and tagged (docker-publish.yml).
# It checks each variant's version tags (and the plain and -standard tags of
# the default image): the tag resolves, its index carries every architecture,
# all tags of a variant name the same digest, and cosign verifies that digest
# against this repository's docker-publish workflow at the release tag. Only
# then is the draft published; a plain vX.Y.Z also becomes "Latest". On any
# failure nothing is published and the release stays a draft, so no install
# command, chart default or self-update ever points at a version without its
# images.
#
# Environment (defaults in brackets):
#   IMAGE      image repository [ghcr.io/openctemio/sensor]
#   REPO       GitHub repository [$GITHUB_REPOSITORY, else openctemio/sensor]
#   VARIANTS   space-separated image variants [default passive full browser
#              semgrep opengrep trivy nuclei betterleaks]
#   ARCHES     space-separated os/arch every index must carry
#              [linux/amd64 linux/arm64]
#   IDENTITY   the signing certificate identity [https://github.com/$REPO/
#              .github/workflows/docker-publish.yml@refs/tags/VERSION]
#   WAIT_SECONDS  how long to wait for the draft release to appear [1800]
#   POLL_SECONDS  between those checks [30]
set -euo pipefail

VERSION="${1:-}"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: publish-gate.sh vX.Y.Z[-suffix]" >&2
  exit 2
fi
IMAGE="${IMAGE:-ghcr.io/openctemio/sensor}"
REPO="${REPO:-${GITHUB_REPOSITORY:-openctemio/sensor}}"
VARIANTS="${VARIANTS:-default passive full browser semgrep opengrep trivy nuclei betterleaks}"
ARCHES="${ARCHES:-linux/amd64 linux/arm64}"
IDENTITY="${IDENTITY:-https://github.com/${REPO}/.github/workflows/docker-publish.yml@refs/tags/${VERSION}}"
WAIT_SECONDS="${WAIT_SECONDS:-1800}"
POLL_SECONDS="${POLL_SECONDS:-30}"
ISSUER="https://token.actions.githubusercontent.com"

failed=0
fail() {
  echo "::error::$*" >&2
  failed=1
}

# tags_of VARIANT: the version tags that variant's merge job moved.
tags_of() {
  if [[ "$1" == default ]]; then
    echo "${VERSION}-default ${VERSION} ${VERSION}-standard"
  else
    echo "${VERSION}-$1"
  fi
}

for variant in $VARIANTS; do
  want=""
  for tag in $(tags_of "$variant"); do
    if ! manifest="$(docker buildx imagetools inspect "${IMAGE}:${tag}" --format '{{json .Manifest}}' 2>/dev/null)" || [[ -z "$manifest" ]]; then
      fail "${IMAGE}:${tag} is not published"
      continue
    fi
    digest="$(jq -r '.digest // empty' <<<"$manifest")"
    if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      fail "${IMAGE}:${tag}: no index digest"
      continue
    fi
    platforms="$(jq -r '[.manifests[]? | select(.platform.os != "unknown") | "\(.platform.os)/\(.platform.architecture)"] | join(" ")' <<<"$manifest")"
    for arch in $ARCHES; do
      if [[ " $platforms " != *" $arch "* ]]; then
        fail "${IMAGE}:${tag} has no ${arch} image (has: ${platforms:-none})"
      fi
    done
    if [[ -z "$want" ]]; then
      want="$digest"
      if ! cosign verify "${IMAGE}@${digest}" --certificate-oidc-issuer "$ISSUER" \
        --certificate-identity "$IDENTITY" >/dev/null 2>&1; then
        fail "${IMAGE}@${digest} (${tag}) has no signature by ${IDENTITY}"
      fi
    elif [[ "$digest" != "$want" ]]; then
      fail "${IMAGE}:${tag} is ${digest}, but the ${variant} image of ${VERSION} is ${want}"
    fi
  done
done

if [[ $failed -ne 0 ]]; then
  echo "The release ${VERSION} stays a draft: publish the missing images (re-run Docker Publish on the tag), then run this gate again." >&2
  exit 1
fi
echo "Every image of ${VERSION} is published for ${ARCHES} and signed."

# The draft is made by the Release workflow, which runs in parallel: wait
# for it.
deadline=$((SECONDS + WAIT_SECONDS))
while :; do
  if draft="$(gh release view "$VERSION" --repo "$REPO" --json isDraft --jq .isDraft 2>/dev/null)"; then
    break
  fi
  if ((SECONDS >= deadline)); then
    echo "::error::no release ${VERSION} in ${REPO} after ${WAIT_SECONDS}s" >&2
    exit 1
  fi
  sleep "$POLL_SECONDS"
done

if [[ "$draft" != true ]]; then
  # Already published (a re-run): never move "Latest" back to an older
  # version.
  echo "Release ${VERSION} is already published; nothing to do."
  exit 0
fi
if [[ "$VERSION" == *-* ]]; then
  gh release edit "$VERSION" --repo "$REPO" --draft=false --prerelease
else
  gh release edit "$VERSION" --repo "$REPO" --draft=false --latest
fi
echo "Published release ${VERSION}."
