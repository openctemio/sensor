#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# prepare-release.sh: the content of a release PR for sdk-go or sensor
# (openctemio/openctem api/docs/rfcs/RFC-037 §6). Same file in both repos.
#
#   prepare-release.sh --version vX.Y.Z [--date YYYY-MM-DD] [--root DIR] [--allow-empty]
#
# - CHANGELOG.md: the Unreleased section becomes the vX.Y.Z section, and an
#   empty Unreleased section stays on top. Both heading styles are handled:
#   "## Unreleased" -> "## vX.Y.Z — DATE" (sdk-go) and
#   "## [Unreleased]" -> "## [vX.Y.Z] — DATE" (sensor).
# - pkg/sdk/version.go, when present (sdk-go): const Version = "X.Y.Z".
#
# Refuses when the version already has a section, or when Unreleased is empty
# (a release without a changelog entry; --allow-empty overrides).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

ROOT="$(cd "$HERE/../../.." && pwd)"
VERSION=""
DATE="$(date -u +%Y-%m-%d)"
ALLOW_EMPTY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift ;;
    --date) DATE="$2"; shift ;;
    --root) ROOT="$(cd "$2" && pwd)"; shift ;;
    --allow-empty) ALLOW_EMPTY=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
rel_is_version "$VERSION" || { echo "--version must be vX.Y.Z, got '$VERSION'" >&2; exit 2; }
[[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "--date must be YYYY-MM-DD" >&2; exit 2; }

CHANGELOG="$ROOT/CHANGELOG.md"
[[ -f "$CHANGELOG" ]] || { echo "no CHANGELOG.md in $ROOT" >&2; exit 2; }

if grep -qE '^## \[Unreleased\][[:space:]]*$' "$CHANGELOG"; then
  unreleased='## [Unreleased]'
  heading="## [$VERSION] — $DATE"
  existing="^## \\[$VERSION\\]"
else
  unreleased='## Unreleased'
  heading="## $VERSION — $DATE"
  existing="^## $VERSION([^0-9.]|\$)"
fi
grep -qxF "$unreleased" "$CHANGELOG" || { echo "CHANGELOG.md has no '$unreleased' heading" >&2; exit 2; }
if grep -qE "$existing" "$CHANGELOG"; then
  echo "REFUSING: CHANGELOG.md already has a $VERSION section" >&2
  exit 1
fi

# Lines between the Unreleased heading and the next "## " heading.
body="$(awk -v h="$unreleased" '
  $0 == h { on = 1; next }
  on && /^## / { exit }
  on { print }
' "$CHANGELOG")"
if [[ -z "${body//[[:space:]]/}" && $ALLOW_EMPTY -eq 0 ]]; then
  echo "REFUSING: the Unreleased section is empty; write the changelog first (or --allow-empty)" >&2
  exit 1
fi

tmp="$(mktemp)"
awk -v h="$unreleased" -v nh="$heading" '
  $0 == h && !done { print; print ""; print nh; done = 1; next }
  { print }
' "$CHANGELOG" >"$tmp"
cat "$tmp" >"$CHANGELOG"
rm -f "$tmp"
echo "CHANGELOG.md: Unreleased -> $heading" >&2

VERSION_GO="$ROOT/pkg/sdk/version.go"
if [[ -f "$VERSION_GO" ]]; then
  grep -qE '^const Version = "[^"]*"$' "$VERSION_GO" || { echo "pkg/sdk/version.go: no 'const Version = \"...\"' line" >&2; exit 2; }
  sed -i -E "s/^const Version = \"[^\"]*\"$/const Version = \"${VERSION#v}\"/" "$VERSION_GO"
  echo "pkg/sdk/version.go: Version = ${VERSION#v}" >&2
fi
