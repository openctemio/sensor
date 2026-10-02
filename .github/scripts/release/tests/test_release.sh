#!/usr/bin/env bash
# Tests for prepare-release.sh, tag-release.sh and next-version.sh in both
# changelog styles (sdk-go "## Unreleased", sensor "## [Unreleased]").
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
PREP="$RELEASE_DIR/prepare-release.sh"
TAG="$RELEASE_DIR/tag-release.sh"
NV="$RELEASE_DIR/next-version.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- sdk-go style ----------------------------------------------------------------
sdk="$tmp/sdk"
git init -q --bare -b main "$tmp/sdk-origin.git"
new_repo "$sdk"
git -C "$sdk" remote add origin "$tmp/sdk-origin.git"
mkdir -p "$sdk/pkg/sdk"
printf 'package sdk\n\nconst Version = "0.14.0"\n' >"$sdk/pkg/sdk/version.go"
printf '# Changelog\n\n## Unreleased\n\n### Fixed\n\n- a fix\n\n## v0.14.0 — 2026-10-01\n\n- old\n' >"$sdk/CHANGELOG.md"
git -C "$sdk" add -A && git -C "$sdk" commit -q -m "chore: init"
git -C "$sdk" tag -a v0.14.0 -m v0.14.0
commit "$sdk" "feat(core): something new"
git -C "$sdk" push -q origin main --tags

assert_contains "sdk: proposal" "NEXT_VERSION=v0.15.0" "$(bash "$NV" --repo "$sdk" --ref main)"

bash "$PREP" --root "$sdk" --version v0.15.0 --date 2026-10-16 2>/dev/null
cl="$(cat "$sdk/CHANGELOG.md")"
assert_eq "sdk: changelog folded" "$(printf '# Changelog\n\n## Unreleased\n\n## v0.15.0 — 2026-10-16\n\n### Fixed\n\n- a fix\n\n## v0.14.0 — 2026-10-01\n\n- old')" "$cl"
assert_contains "sdk: version.go bumped" 'const Version = "0.15.0"' "$(cat "$sdk/pkg/sdk/version.go")"
assert_rc "sdk: twice refused" 1 bash "$PREP" --root "$sdk" --version v0.15.0
assert_rc "sdk: empty Unreleased refused" 1 bash "$PREP" --root "$sdk" --version v0.16.0
assert_rc "sdk: empty Unreleased allowed on request" 0 bash "$PREP" --root "$sdk" --version v0.16.0 --allow-empty
git -C "$sdk" checkout -q -- . 2>/dev/null
bash "$PREP" --root "$sdk" --version v0.15.0 --date 2026-10-16 2>/dev/null
git -C "$sdk" commit -qam "chore(release): v0.15.0"
git -C "$sdk" push -q origin main
rc_commit="$(git -C "$sdk" rev-parse HEAD)"

assert_rc "tag: wrong version for the tree" 1 bash "$TAG" --repo "$sdk" --version v0.16.0 --commit "$rc_commit"
assert_rc "tag: commit before the release PR" 1 bash "$TAG" --repo "$sdk" --version v0.15.0 --commit HEAD~1
out="$(bash "$TAG" --repo "$sdk" --version v0.15.0 --commit "$rc_commit" --push 2>&1)"; rc=$?
assert_eq "tag: exit 0 ($out)" 0 "$rc"
assert_eq "tag: annotated on the commit" "$rc_commit" "$(git -C "$sdk" rev-parse 'v0.15.0^{commit}')"
assert_contains "tag: pushed" "refs/tags/v0.15.0" "$(git -C "$sdk" ls-remote --tags origin)"
assert_rc "tag: twice refused" 1 bash "$TAG" --repo "$sdk" --version v0.15.0 --commit "$rc_commit"
assert_rc "tag: not greater refused" 1 bash "$TAG" --repo "$sdk" --version v0.14.0 --commit "$rc_commit"

# --- sensor style ----------------------------------------------------------------
sen="$tmp/sensor"
git init -q --bare -b main "$tmp/sensor-origin.git"
new_repo "$sen"
git -C "$sen" remote add origin "$tmp/sensor-origin.git"
printf '# Changelog\n\nintro\n\n## [Unreleased]\n\n### Removed\n\n- x\n\n## [v0.3.0] — 2026-10-01\n' >"$sen/CHANGELOG.md"
git -C "$sen" add -A && git -C "$sen" commit -q -m "chore: init"
git -C "$sen" tag -a v0.6.4 -m v0.6.4
git -C "$sen" commit -q --allow-empty -m "chore!: remove platform mode"
git -C "$sen" push -q origin main --tags
assert_contains "sensor: breaking before 1.0 -> minor" "NEXT_VERSION=v0.7.0" "$(bash "$NV" --repo "$sen" --ref main)"
bash "$PREP" --root "$sen" --version v0.7.0 --date 2026-10-16 2>/dev/null
assert_contains "sensor: bracket heading" "$(printf '## [Unreleased]\n\n## [v0.7.0] — 2026-10-16\n\n### Removed')" "$(cat "$sen/CHANGELOG.md")"
assert_rc "sensor: no version.go needed" 1 test -e "$sen/pkg/sdk/version.go"
git -C "$sen" commit -qam "chore(release): v0.7.0"
git -C "$sen" push -q origin main
assert_rc "sensor: tag" 0 bash "$TAG" --repo "$sen" --version v0.7.0 --commit HEAD
assert_rc "sensor: refuses a changelog without the section" 1 bash "$TAG" --repo "$sen" --version v0.7.1 --commit HEAD

finish
