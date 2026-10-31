#!/usr/bin/env bash
# install-pins.sh: the release the install guides pin (scripts/install-guides.txt).
#
#   install-pins.sh update vX.Y.Z   rewrite every pin to vX.Y.Z (the release PR runs it)
#   install-pins.sh check [vX.Y.Z]  fail when a pin names another release; default:
#                                   the newest release section of CHANGELOG.md
#
# A pin is the image (openctemio/sensor:vX.Y.Z, with a profile suffix such as
# -full), a file of the repository at a tag (openctemio/sensor/vX.Y.Z/...), a
# release download (sensor/releases/download/vX.Y.Z), a cosign certificate
# identity (@refs/tags/vX.Y.Z) or SENSOR_VERSION=vX.Y.Z. Other version
# mentions ("from v0.8.0") are history and stay as written.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN='(openctemio/sensor:|openctemio/sensor/|sensor/releases/download/|@refs/tags/|SENSOR_VERSION=)v[0-9]+\.[0-9]+\.[0-9]+'

guides() { # the existing files the globs of install-guides.txt name
  local glob f
  while IFS= read -r glob; do
    [[ -z "$glob" || "$glob" == \#* ]] && continue
    # shellcheck disable=SC2086 # the glob must expand
    for f in "$ROOT"/$glob; do
      [[ -f "$f" ]] && printf '%s\n' "$f"
    done
  done <"$ROOT/scripts/install-guides.txt"
}

latest_release() {
  sed -n -E 's/^## \[?(v[0-9]+\.[0-9]+\.[0-9]+)\]?( .*)?$/\1/p' "$ROOT/CHANGELOG.md" | head -1
}

is_version() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

case "${1:-}" in
  update)
    v="${2:-}"
    is_version "$v" || { echo "update needs vX.Y.Z, got '$v'" >&2; exit 2; }
    while IFS= read -r f; do
      sed -i -E "s#${PIN}#\\1${v}#g" "$f"
    done < <(guides)
    echo "install pins -> $v" >&2
    ;;
  check)
    v="${2:-$(latest_release)}"
    is_version "$v" || { echo "no release in CHANGELOG.md to check against (got '$v')" >&2; exit 2; }
    bad=0
    while IFS= read -r f; do
      # One line per pin: LINE:PIN.
      while IFS=: read -r line pin; do
        [[ "$pin" == *"$v" ]] && continue
        echo "${f#"$ROOT"/}:${line}: ${pin} is not ${v}" >&2
        bad=1
      done < <(grep -noE "$PIN" "$f" || true)
    done < <(guides)
    if [[ $bad -ne 0 ]]; then
      echo "Install guides pin another release than $v. Run: scripts/install-pins.sh update $v" >&2
      exit 1
    fi
    echo "install pins: every guide pins $v"
    ;;
  *)
    sed -n '2,7s/^# \{0,1\}//p' "$0" >&2
    exit 2
    ;;
esac
