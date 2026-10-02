#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# tag-release.sh: tag a merged release PR on main, for sdk-go or sensor
# (openctemio/openctem api/docs/rfcs/RFC-037 §6). Same file in both repos.
#
#   tag-release.sh --version vX.Y.Z --commit SHA [--push] [--remote origin] [--repo DIR]
#
# Refuses unless the version is vX.Y.Z and greater than every release tag,
# the tag does not exist (locally or on the remote), the commit is on main,
# and the commit carries the release: CHANGELOG.md has the vX.Y.Z section and,
# in sdk-go, pkg/sdk/version.go says X.Y.Z.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

VERSION=""
COMMIT=""
PUSH=0
REMOTE="origin"
REPO="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift ;;
    --commit) COMMIT="$2"; shift ;;
    --push) PUSH=1 ;;
    --remote) REMOTE="$2"; shift ;;
    --repo) REPO="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
die() { echo "REFUSING: $*" >&2; exit 1; }
g() { git -C "$REPO" "$@"; }

rel_is_version "$VERSION" || { echo "--version must be vX.Y.Z, got '$VERSION'" >&2; exit 2; }
[[ -n "$COMMIT" ]] || { echo "--commit is required" >&2; exit 2; }
g fetch --quiet --tags "$REMOTE" "+refs/heads/main:refs/remotes/$REMOTE/main"
COMMIT="$(g rev-parse --verify "$COMMIT^{commit}")"

g rev-parse -q --verify "refs/tags/$VERSION" >/dev/null && die "tag $VERSION already exists"
g ls-remote --exit-code --tags "$REMOTE" "refs/tags/$VERSION" >/dev/null 2>&1 && die "tag $VERSION already exists on $REMOTE"
last="$(rel_latest_tag "$REPO")"
if [[ -n "$last" ]] && ! rel_version_gt "$VERSION" "$last"; then
  die "$VERSION is not greater than the last release $last"
fi
g merge-base --is-ancestor "$COMMIT" "refs/remotes/$REMOTE/main" || die "$COMMIT is not on main"

changelog="$(g show "$COMMIT:CHANGELOG.md" 2>/dev/null)" || die "no CHANGELOG.md at $COMMIT"
grep -qE "^## (\\[$VERSION\\]|$VERSION)([^0-9.]|\$)" <<<"$changelog" || die "CHANGELOG.md at $COMMIT has no $VERSION section"
if g cat-file -e "$COMMIT:pkg/sdk/version.go" 2>/dev/null; then
  have="$(g show "$COMMIT:pkg/sdk/version.go" | sed -nE 's/^const Version = "([^"]*)"$/\1/p')"
  [[ "$have" == "${VERSION#v}" ]] || die "pkg/sdk/version.go at $COMMIT says '$have', not ${VERSION#v}"
fi

g -c user.name="${GIT_AUTHOR_NAME:-openctem-release}" -c user.email="${GIT_AUTHOR_EMAIL:-release@openctem.invalid}" \
  tag -a "$VERSION" "$COMMIT" -m "$VERSION"
echo "tagged $VERSION at $COMMIT" >&2
if [[ $PUSH -eq 1 ]]; then
  g push --quiet "$REMOTE" "refs/tags/$VERSION"
  echo "pushed $VERSION" >&2
fi
echo "TAG=$VERSION"
echo "COMMIT=$COMMIT"
