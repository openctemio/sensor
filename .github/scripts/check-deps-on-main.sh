#!/usr/bin/env bash
# Every openctemio module the sensor depends on must point at a commit that is
# on that module's main branch. A pin to a feature-branch commit breaks once the
# branch is squash-merged (the commit then exists on no branch), and a release
# built from it cannot be reproduced.
#
# Uses git only (a blobless clone of each module's main), so it needs no API
# token and works for any public module repository.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf -- "${work:?}"' EXIT
fail=0
while read -r mod ver; do
  repo="${mod#github.com/}"
  dir="${work}/${repo//\//_}"
  git clone -q --filter=blob:none --no-checkout --single-branch --branch main \
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
