#!/usr/bin/env bash
# Tests for publish-gate.sh and the release wiring around it: a release
# becomes visible (and "Latest") only once every image variant is published
# for every architecture and signed.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
ROOT="$(cd "$RELEASE_DIR/../../.." && pwd)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fakes on PATH. The registry is a directory: $REG/<tag> holds the
# `imagetools inspect --format {{json .Manifest}}` answer of that tag, a
# missing file is an unpublished tag. $SIGNED lists the signed digests.
# $RELEASE holds the release's isDraft ("true"/"false"; missing: no
# release yet). Every gh edit is logged to $LOG.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
ref="${4:-}"
tag="${ref##*:}"
[[ -f "$REG/$tag" ]] || { echo "not found" >&2; exit 1; }
cat "$REG/$tag"
EOF
cat >"$tmp/bin/cosign" <<'EOF'
#!/usr/bin/env bash
digest="${2##*@}"
grep -qx "$digest" "$SIGNED" 2>/dev/null
EOF
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
case "$2" in
  view) [[ -f "$RELEASE" ]] || exit 1; cat "$RELEASE" ;;
  edit) echo "gh $*" >>"$LOG" ;;
esac
EOF
chmod +x "$tmp/bin/"*

d1="sha256:$(printf '1%.0s' {1..64})"
d2="sha256:$(printf '2%.0s' {1..64})"
index() { # digest arch...
  local d="$1" m="" a
  shift
  for a in "$@"; do
    m="$m${m:+,}{\"platform\":{\"os\":\"${a%/*}\",\"architecture\":\"${a#*/}\"}}"
  done
  # An attestation manifest (platform unknown/unknown) as buildx adds.
  printf '{"digest":"%s","manifests":[%s,{"platform":{"os":"unknown","architecture":"unknown"}}]}' "$d" "$m"
}

# setup: a registry where default and nuclei of v1.2.3 are complete and
# signed, and a draft release exists.
setup() {
  export REG="$tmp/reg.$1" SIGNED="$tmp/signed.$1" RELEASE="$tmp/release.$1" LOG="$tmp/log.$1"
  mkdir -p "$REG"
  for t in v1.2.3-default v1.2.3 v1.2.3-standard v1.2.3-rc.1-default v1.2.3-rc.1 v1.2.3-rc.1-standard; do
    index "$d1" linux/amd64 linux/arm64 >"$REG/$t"
  done
  index "$d2" linux/amd64 linux/arm64 >"$REG/v1.2.3-nuclei"
  printf '%s\n%s\n' "$d1" "$d2" >"$SIGNED"
  echo true >"$RELEASE"
  : >"$LOG"
}
gate() { # VERSION
  PATH="$tmp/bin:$PATH" VARIANTS="default nuclei" WAIT_SECONDS=0 POLL_SECONDS=0 \
    bash "$RELEASE_DIR/publish-gate.sh" "$1"
}

setup ok
assert_rc "complete and signed: published" 0 gate v1.2.3
assert_eq "complete: draft published and marked latest" \
  "gh release edit v1.2.3 --repo openctemio/sensor --draft=false --latest" "$(cat "$LOG")"

setup arch
index "$d2" linux/amd64 >"$REG/v1.2.3-nuclei"
assert_rc "an arm64 image missing: refused" 1 gate v1.2.3
assert_eq "an arm64 image missing: stays a draft" "" "$(cat "$LOG")"
out="$(gate v1.2.3 2>&1)"
assert_contains "the error names the tag and the arch" "v1.2.3-nuclei has no linux/arm64 image" "$out"

setup plain
rm "$REG/v1.2.3"
assert_rc "the plain tag missing: refused" 1 gate v1.2.3
assert_eq "the plain tag missing: stays a draft" "" "$(cat "$LOG")"

setup standard
index "$d2" linux/amd64 linux/arm64 >"$REG/v1.2.3-standard"
assert_rc "-standard on another digest: refused" 1 gate v1.2.3
assert_eq "-standard on another digest: stays a draft" "" "$(cat "$LOG")"

setup variant
rm "$REG/v1.2.3-nuclei"
assert_rc "a variant never published: refused" 1 gate v1.2.3
assert_eq "a variant never published: stays a draft" "" "$(cat "$LOG")"

setup unsigned
printf '%s\n' "$d1" >"$SIGNED"
assert_rc "an unsigned image: refused" 1 gate v1.2.3
assert_eq "an unsigned image: stays a draft" "" "$(cat "$LOG")"

setup norelease
rm "$RELEASE"
assert_rc "no draft release: fails" 1 gate v1.2.3
assert_eq "no draft release: nothing edited" "" "$(cat "$LOG")"

setup published
echo false >"$RELEASE"
assert_rc "already published (a re-run): ok" 0 gate v1.2.3
assert_eq "already published: Latest not moved" "" "$(cat "$LOG")"

setup pre
assert_rc "a prerelease: published" 0 env VARIANTS=default PATH="$tmp/bin:$PATH" WAIT_SECONDS=0 \
  bash "$RELEASE_DIR/publish-gate.sh" v1.2.3-rc.1
assert_eq "a prerelease: never Latest" \
  "gh release edit v1.2.3-rc.1 --repo openctemio/sensor --draft=false --prerelease" "$(cat "$LOG")"

assert_rc "a bad version: usage error" 2 bash "$RELEASE_DIR/publish-gate.sh" latest

# The wiring: GoReleaser creates a draft, and the only step that publishes it
# is the gate, after every image variant's merge job.
goreleaser="$(cat "$ROOT/.goreleaser.yaml")"
assert_contains "GoReleaser creates the release as a draft" "  draft: true" "$goreleaser"
assert_not_contains "GoReleaser never publishes it itself" "  draft: false" "$goreleaser"
publish="$(cat "$ROOT/.github/workflows/docker-publish.yml")"
assert_contains "docker-publish runs the gate" ".github/scripts/release/publish-gate.sh" "$publish"
gate_job="$(awk '/^  publish-release:/{p=1} p&&/^  [a-z-]+:$/&&!/^  publish-release:/{p=0} p' "$ROOT/.github/workflows/docker-publish.yml")"
assert_contains "the gate waits for every merge job" "needs: [prepare, merge]" "$gate_job"
for wf in "$ROOT"/.github/workflows/*.yml; do
  [[ "$(basename "$wf")" == docker-publish.yml ]] && continue
  assert_not_contains "$(basename "$wf") does not publish the draft" "--draft=false" "$(cat "$wf")"
done

finish
