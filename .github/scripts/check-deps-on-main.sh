#!/usr/bin/env bash
# Every openctemio module the sensor depends on must point at a commit that is
# on that module's main branch. A pin to a feature-branch commit breaks once the
# branch is squash-merged (the commit then exists on no branch), and a release
# built from it cannot be reproduced.
set -euo pipefail
fail=0
while read -r mod ver; do
  repo="${mod#github.com/}"
  if [[ "$ver" =~ -[0-9]{14}-([0-9a-f]{12})$ ]]; then
    ref="${BASH_REMATCH[1]}"
  else
    ref="$ver" # a tag
  fi
  status=$(curl -fsS -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${repo}/compare/main...${ref}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])') || status="unknown"
  case "$status" in
    identical|behind) echo "ok   $mod $ver ($status main)";;
    *) echo "FAIL $mod $ver is not on ${repo} main (compare: $status). Re-pin to a commit on main." >&2; fail=1;;
  esac
done < <(awk '/^\t?github.com\/openctemio\/[a-z-]+ v/ {sub(/^\t/,""); print $1, $2}' go.mod | sort -u)
exit "$fail"
