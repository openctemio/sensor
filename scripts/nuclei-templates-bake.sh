#!/usr/bin/env bash
# Bake a pinned nuclei-templates release into an image, and gate it.
#
#   scripts/nuclei-templates-bake.sh <version> <archive-sha256> <allowlist>
#
# Runs at image build, after nuclei is installed, with HOME set to the
# runtime user's home (/home/openctem):
#
#   1. Downloads the release archive and checks it against the SHA-256
#      pinned in the Dockerfile (a tampered or re-tagged archive fails the
#      build). Nothing is fetched at run time: the sensor scans with this set
#      until its managed content (internal/content) installs a verified newer
#      one, and nuclei runs with -duc.
#   2. Extracts it to $HOME/nuclei-templates (no links allowed) and writes
#      nuclei's configuration for it in $HOME/.config/nuclei:
#        .templates-config.json  the templates directory and the release, so
#                                nuclei resolves helper files (payload
#                                wordlists, workflow subtemplates) there and
#                                prints the release instead of "(unknown)";
#        .nuclei-ignore          the release's own exclusion list, which must
#                                still exclude every baseline tag (dos, local,
#                                fuzz, bruteforce, txt-service);
#        openctem-templates-release.json
#                                the release and its archive digest, read by
#                                the sensor (content.BakedReleaseFile) and
#                                reported with every nuclei result.
#   3. Gates the set with this nuclei:
#        - `nuclei -validate` (signed templates only) may fail only for the
#          templates listed in <allowlist>;
#        - a scan with the sensor's flags against a closed local port prints
#          no [ERR] line, no "templates with runtime error" beyond the
#          allow-list, and the release version.
#
# Template classes the sensor does not enable (code, headless, file,
# self-contained) are skipped by nuclei, not errors: they need -code,
# -headless, -file or -esc, which the sensor never passes for its own set.
set -euo pipefail

version="${1:?usage: nuclei-templates-bake.sh <version> <archive-sha256> <allowlist>}"
sha256="${2:?usage: nuclei-templates-bake.sh <version> <archive-sha256> <allowlist>}"
allowlist="${3:?usage: nuclei-templates-bake.sh <version> <archive-sha256> <allowlist>}"
version="${version#v}"

[[ "$version" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || { echo "invalid nuclei-templates version: $version" >&2; exit 2; }
[[ "$sha256" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid nuclei-templates sha256: $sha256" >&2; exit 2; }
[ -f "$allowlist" ] || { echo "allow-list $allowlist not found" >&2; exit 2; }
: "${HOME:?HOME must be set}"

url="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${version}.tar.gz"
dest="$HOME/nuclei-templates"
cfg="$HOME/.config/nuclei"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "nuclei-templates v${version}: $*" >&2
  exit 1
}

# --- 1. download and verify --------------------------------------------------
# NUCLEI_TEMPLATES_ARCHIVE: a local copy of the archive (tests, offline
# builds). It is checked against the same pinned SHA-256.
if [ -n "${NUCLEI_TEMPLATES_ARCHIVE:-}" ]; then
  cp "$NUCLEI_TEMPLATES_ARCHIVE" "$work/templates.tar.gz"
else
  curl -fsSL -o "$work/templates.tar.gz" "$url"
fi
echo "${sha256}  $work/templates.tar.gz" | sha256sum -c -

# --- 2. extract and configure ------------------------------------------------
rm -rf "$dest"
mkdir -p "$dest" "$cfg"
tar -xzf "$work/templates.tar.gz" -C "$dest" --strip-components=1 --no-same-owner --no-same-permissions
if [ -n "$(find "$dest" -type l -print -quit)" ]; then
  fail "the archive contains symbolic links; refusing it"
fi
count=$(find "$dest" -name '*.yaml' -type f | wc -l)
[ "$count" -ge 1000 ] || fail "only $count templates in the archive"

[ -f "$dest/.nuclei-ignore" ] || fail "the release ships no .nuclei-ignore"
for tag in dos local fuzz bruteforce txt-service; do
  grep -Eq "^[[:space:]]*-[[:space:]]*\"?${tag}\"?[[:space:]]*\$" "$dest/.nuclei-ignore" ||
    fail ".nuclei-ignore no longer excludes the '${tag}' tag; review the release before baking it"
done
cp "$dest/.nuclei-ignore" "$cfg/.nuclei-ignore"
printf '{"nuclei-templates-directory":"%s","nuclei-templates-version":"v%s"}\n' "$dest" "$version" \
  >"$cfg/.templates-config.json"

# --- 3. gate -------------------------------------------------------------------
allowed=$(grep -Ev '^[[:space:]]*(#|$)' "$allowlist" | sed 's/[[:space:]]*$//' | sort -u || true)

set +e
nuclei -validate -duc -disable-unsigned-templates -t "$dest" -no-color >/dev/null 2>"$work/validate.err"
rc=$?
set -e
failed=$(sed 's/\x1b\[[0-9;]*m//g' "$work/validate.err" | grep '^\[ERR\]' |
  sed -E -e "s#^\[ERR\] Error occurred parsing template ${dest}/([^:]+):.*#\1#" \
    -e "s#^\[ERR\] Could not find template '([^']+)'.*#\1#" | sort -u || true)
show_validate_errors() {
  sed 's/\x1b\[[0-9;]*m//g' "$work/validate.err" | grep -E '^\[(ERR|FTL)\]' | tail -n 20 >&2 || true
}
unexpected=$(comm -23 <(printf '%s\n' "$failed" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d'))
if [ -n "$unexpected" ]; then
  echo "templates that fail nuclei -validate and are not in $(basename "$allowlist"):" >&2
  printf '%s\n' "$unexpected" | sed 's/^/  /' >&2
  show_validate_errors
  exit 1
fi
if [ "$rc" -ne 0 ] && [ -z "$failed" ]; then
  show_validate_errors
  fail "nuclei -validate exited $rc"
fi
stale=$(comm -13 <(printf '%s\n' "$failed" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d'))
if [ -n "$stale" ]; then
  echo "warning: allow-listed templates that now validate (remove them from $(basename "$allowlist")):" >&2
  printf '%s\n' "$stale" | sed 's/^/  /' >&2
fi

# The sensor's own scan flags (internal/scanners/nuclei.Scanner.buildArgsFor)
# against a port nothing listens on: every template is loaded and compiled,
# nothing leaves the build container.
out=$(nuclei -u http://127.0.0.1:9 -jsonl -t "$dest" -severity critical,high,medium,low \
  -rate-limit 150 -c 25 -bs 25 -ni -disable-update-check -disable-unsigned-templates \
  -nc -timeout 2 -retries 0 2>&1 >/dev/null | sed 's/\x1b\[[0-9;]*m//g')
if printf '%s\n' "$out" | grep -q '^\[ERR\]'; then
  printf '%s\n' "$out" | grep '^\[ERR\]' | head -n 5 >&2
  fail "a scan run logs errors"
fi
runtime_errors=$(printf '%s\n' "$out" | sed -nE 's/.*Found ([0-9]+) templates with runtime error.*/\1/p' | head -n 1)
allowed_count=$(printf '%s\n' "$allowed" | sed '/^$/d' | wc -l)
if [ -n "$runtime_errors" ] && [ "$runtime_errors" -gt "$allowed_count" ]; then
  fail "a scan run finds $runtime_errors templates with runtime error (allow-list: $allowed_count)"
fi
printf '%s\n' "$out" | grep -q "Current nuclei-templates version: v${version}" ||
  fail "nuclei does not report the release: $(printf '%s\n' "$out" | grep 'nuclei-templates version' || echo '<no version line>')"
loaded=$(printf '%s\n' "$out" | sed -nE 's/.*Templates loaded for current scan: ([0-9]+).*/\1/p' | head -n 1)

# The release's date: GitHub's archive carries the tagged commit's time on
# every file (tar keeps it). The sensor dates the baked set with it, not with
# the image build time (which would make newer releases look like rollbacks).
released=$(date -u -r "$dest/README.md" +%Y-%m-%dT%H:%M:%SZ)
printf '{"version":"v%s","digest":"sha256:%s","updated_at":"%s","source":"%s"}\n' "$version" "$sha256" "$released" "$url" \
  >"$cfg/openctem-templates-release.json"

echo "nuclei-templates v${version} (sha256:${sha256}): ${count} files, ${loaded:-?} templates in a default scan, ${runtime_errors:-0} runtime errors, $(printf '%s\n' "$failed" | sed '/^$/d' | wc -l) allow-listed validation failures"
