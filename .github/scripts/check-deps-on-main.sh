#!/usr/bin/env bash
# Every openctemio module the sensor depends on must point at a commit that is
# on that module's main branch. A pin to a feature-branch commit breaks once the
# branch is squash-merged (the commit then exists on no branch), and a release
# built from it cannot be reproduced.
#
# Uses git only (a blobless clone of each module's main), so it needs no API
# token and works for any public module repository.
set -euo pipefail
# No background git writers in the throwaway clones: a detached auto-gc,
# maintenance run or commit-graph write (also started by a promisor fetch) was
# still writing into .git/objects when the cleanup below ran, and "rm -rf"
# failed with "Directory not empty" after every check had passed. The settings
# go on every git call (GIT_CONFIG_*) and, through clone -c, into each clone.
export GIT_CONFIG_COUNT=4 \
  GIT_CONFIG_KEY_0=gc.auto GIT_CONFIG_VALUE_0=0 \
  GIT_CONFIG_KEY_1=maintenance.auto GIT_CONFIG_VALUE_1=false \
  GIT_CONFIG_KEY_2=fetch.writeCommitGraph GIT_CONFIG_VALUE_2=false \
  GIT_CONFIG_KEY_3=gc.autoDetach GIT_CONFIG_VALUE_3=false
work=$(mktemp -d)
# Cleanup never changes the exit status: the real result of the checks is kept.
cleanup() {
  local rc=$?
  rm -rf -- "${work:?}" 2>/dev/null || { sleep 1; rm -rf -- "${work:?}" 2>/dev/null; } || true
  exit "$rc"
}
trap cleanup EXIT
fail=0
while read -r mod ver; do
  repo="${mod#github.com/}"
  dir="${work}/${repo//\//_}"
  git clone -q -c gc.auto=0 -c maintenance.auto=false -c fetch.writeCommitGraph=false \
    --filter=blob:none --no-checkout --single-branch --branch main \
    "https://github.com/${repo}.git" "$dir" </dev/null
  if [[ "$ver" =~ [.-][0-9]{14}-([0-9a-f]{12})$ ]]; then
    ref="${BASH_REMATCH[1]}"
  else
    ref="$ver" # a tag
    git -C "$dir" fetch -q --tags origin </dev/null
  fi
  if ! sha=$(git -C "$dir" rev-parse -q --verify "${ref}^{commit}" 2>/dev/null); then
    echo "FAIL $mod $ver: ${ref} is not reachable from ${repo} main (a squash-merged branch commit?). Re-pin to the commit on main." >&2
    fail=1
  elif git -C "$dir" merge-base --is-ancestor "$sha" origin/main; then
    echo "ok   $mod $ver (on ${repo} main)"
  else
    echo "FAIL $mod $ver: ${ref} is not on ${repo} main. Re-pin to a commit on main." >&2
    fail=1
  fi
done < <(awk '/^\t?github.com\/openctemio\/[a-z-]+ v/ {sub(/^\t/,""); print $1, $2}' go.mod | sort -u)
exit "$fail"
