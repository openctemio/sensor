#!/usr/bin/env bash
# Tests for changelog-fragments.py and the fold in prepare-release.sh.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
FRAG="$RELEASE_DIR/changelog-fragments.py"
PREP="$RELEASE_DIR/prepare-release.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
frag() { python3 "$FRAG" --root "$r" "$@"; }

# fresh STYLE: a repository with an empty Unreleased section and changelog.d/.
fresh() {
  r="$tmp/$1"
  rm -rf "$r"
  new_repo "$r"
  mkdir -p "$r/changelog.d"
  printf 'readme\n' >"$r/changelog.d/README.md"
  printf '# Changelog\n\nintro\n\n## %s\n\n## v0.1.0 — 2026-10-01\n\n- old\n' "$2" >"$r/CHANGELOG.md"
  git -C "$r" add -A && git -C "$r" commit -q -m init
}

# --- check -----------------------------------------------------------------------
fresh sdk "Unreleased"
assert_rc "check: no fragments" 0 frag check
printf '### Added: a thing\n\n- text\n' >"$r/changelog.d/a-thing.md"
printf '### Fixed\n\n- untitled fix\n' >"$r/changelog.d/fix-1.md"
assert_rc "check: titled and untitled" 0 frag check
printf '### Nonsense: x\n\n- y\n' >"$r/changelog.d/bad-cat.md"
assert_contains "check: unknown category" "unknown category 'Nonsense'" "$(frag check 2>&1)"
rm "$r/changelog.d/bad-cat.md"
printf '### Added: no body\n' >"$r/changelog.d/nobody.md"
assert_contains "check: empty section" "has no text" "$(frag check 2>&1)"
rm "$r/changelog.d/nobody.md"
printf 'text first\n\n### Added: x\n\n- y\n' >"$r/changelog.d/lead.md"
assert_rc "check: text before the heading" 1 frag check
rm "$r/changelog.d/lead.md"
printf '### Added: x\n\n- y\n' >"$r/changelog.d/Bad_Name.md"
assert_contains "check: name" "name must be lowercase" "$(frag check 2>&1)"
rm "$r/changelog.d/Bad_Name.md"
printf '## v9.9.9\n\n### Added: x\n\n- y\n' >"$r/changelog.d/release-heading.md"
assert_contains "check: release heading in a fragment" "only '### '" "$(frag check 2>&1)"
# shellcheck disable=SC2016 # literal backticks
printf '### Added: x\n\n```sh\n# a comment\n```\n' >"$r/changelog.d/release-heading.md"
assert_rc "check: '#' inside a code fence is fine" 0 frag check
rm "$r/changelog.d/release-heading.md"
printf '\xff\xfe\n' >"$r/changelog.d/binary.md"
assert_contains "check: not UTF-8" "not UTF-8" "$(frag check 2>&1)"
rm "$r/changelog.d/binary.md"

# An entry under Unreleased in CHANGELOG.md is refused; prose is not.
cp "$r/CHANGELOG.md" "$tmp/cl"
sed -i 's/^## Unreleased$/## Unreleased\n\n### Added\n\n- hand-written/' "$r/CHANGELOG.md"
assert_contains "check: entry under Unreleased" "written under Unreleased" "$(frag check 2>&1)"
cp "$tmp/cl" "$r/CHANGELOG.md"
sed -i 's/^## Unreleased$/## Unreleased\n\nSee changelog.d./' "$r/CHANGELOG.md"
assert_rc "check: prose under Unreleased" 0 frag check
cp "$tmp/cl" "$r/CHANGELOG.md"

# Conflict markers in tracked files; untracked files are not scanned.
printf 'package x\n<<<<<<< HEAD\na\n=======\nb\n>>>>>>> branch\n' >"$r/x.go"
assert_rc "check: untracked file ignored" 0 frag check
git -C "$r" add x.go
assert_contains "check: conflict marker" "x.go:2: merge-conflict marker" "$(frag check 2>&1)"
git -C "$r" rm -q --cached x.go && rm "$r/x.go"
assert_contains "check: GitHub annotation" "::error::" "$(printf '### Bad: x\n\n- y\n' >"$r/changelog.d/zz.md"; GITHUB_ACTIONS=true frag check 2>&1)"
rm "$r/changelog.d/zz.md"

# --- preview and fold ------------------------------------------------------------
printf '### Fixed\n\n- second untitled fix\n' >"$r/changelog.d/fix-2.md"
printf '### Security: tokens are redacted\n\n- detail\n' >"$r/changelog.d/sec.md"
assert_contains "preview: security first" "$(printf '## Unreleased\n\n### Security: tokens are redacted')" "$(frag preview)"
assert_contains "preview: untitled merged" "$(printf '### Fixed\n\n- untitled fix\n\n- second untitled fix')" "$(frag preview)"
git -C "$r" add -A && git -C "$r" commit -q -m fragments

bash "$PREP" --root "$r" --version v0.2.0 --date 2026-10-16 2>/dev/null
want="$(printf '# Changelog\n\nintro\n\n## Unreleased\n\n## v0.2.0 — 2026-10-16\n\n### Security: tokens are redacted\n\n- detail\n\n### Added: a thing\n\n- text\n\n### Fixed\n\n- untitled fix\n\n- second untitled fix\n\n## v0.1.0 — 2026-10-01\n\n- old')"
assert_eq "fold: sdk-go release section" "$want" "$(cat "$r/CHANGELOG.md")"
assert_eq "fold: fragments deleted, README kept" "README.md" "$(ls "$r/changelog.d")"
assert_rc "fold: the result passes check" 0 frag check
assert_eq "fold: git commit -a stages the deletions" "4" "$(git -C "$r" commit -qam rel && git -C "$r" show --name-status --format= HEAD | grep -c '^D')"

# Sensor heading style, with a legacy hand-written entry still under Unreleased.
fresh sensor "[Unreleased]"
sed -i 's/^## \[Unreleased\]$/## [Unreleased]\n\n### Changed\n\n- legacy/' "$r/CHANGELOG.md"
printf '### Added: new\n\n- n\n' >"$r/changelog.d/new.md"
bash "$PREP" --root "$r" --version v0.2.0 --date 2026-10-16 2>/dev/null
assert_contains "fold: sensor legacy kept, fragment after" "$(printf '## [Unreleased]\n\n## [v0.2.0] — 2026-10-16\n\n### Changed\n\n- legacy\n\n### Added: new\n\n- n\n\n## v0.1.0')" "$(cat "$r/CHANGELOG.md")"

# Refusals change nothing.
fresh sdk2 "Unreleased"
assert_rc "prepare: no fragment and empty Unreleased refused" 1 bash "$PREP" --root "$r" --version v0.2.0
printf '### Bogus: x\n\n- y\n' >"$r/changelog.d/bogus.md"
before="$(cat "$r/CHANGELOG.md")"
assert_rc "prepare: invalid fragment refused" 1 bash "$PREP" --root "$r" --version v0.2.0
assert_eq "prepare: refusal leaves CHANGELOG.md" "$before" "$(cat "$r/CHANGELOG.md")"
assert_rc "prepare: refusal keeps the fragment" 0 test -f "$r/changelog.d/bogus.md"
rm "$r/changelog.d/bogus.md"
printf '### Added: x\n\n- y\n' >"$r/changelog.d/x.md"
sed -i 's/^## v0.1.0/## v0.2.0 — 2026-10-02\n\n## v0.1.0/' "$r/CHANGELOG.md"
assert_rc "prepare: existing version refused" 1 bash "$PREP" --root "$r" --version v0.2.0
assert_rc "prepare: ... and the fragment kept" 0 test -f "$r/changelog.d/x.md"

finish
