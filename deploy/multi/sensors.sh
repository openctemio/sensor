#!/usr/bin/env bash
# sensors.sh: run several OpenCTEM sensors on one host from this directory
# (README.md). Every sensor has its own env file, data volume, network and
# policy directory; compose.yaml holds the shared hardened settings.
#
#   ./sensors.sh add NAME [--api-url URL] [--pairing-code XXXX-XXXX]
#   ./sensors.sh up                 fetch the release's seccomp profile, start every sensor
#   ./sensors.sh upgrade vX.Y.Z     verify the image signature, then move every sensor to it
#   ./sensors.sh status             containers, and each sensor's last pairing/preflight line
#   ./sensors.sh logs NAME          follow one sensor's log
set -euo pipefail

cd "$(dirname "$0")"

die() { echo "sensors.sh: $*" >&2; exit 1; }
usage() { sed -n '2,11s/^# \{0,1\}//p' "$0"; exit 2; }

COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.1.3"
IDENTITY_WORKFLOW="https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
MARK_SERVICES="  # sensors.sh add: new services above this line"
MARK_VOLUMES="  # sensors.sh add: new volumes above this line"
MARK_NETWORKS="  # sensors.sh add: new networks above this line"

env_value() { # env_value KEY: the value of KEY in .env (empty when unset)
  [[ -f .env ]] || die "no .env here: cp .env.example .env and set SENSOR_VERSION"
  sed -n "s/^$1=//p" .env | tail -1 | tr -d '"'"'"
}

image_ref() { # image_ref VERSION: the image every sensor without its own pin runs
  local repo variant
  repo="$(env_value SENSOR_IMAGE)"
  variant="$(env_value SENSOR_VARIANT)"
  echo "${repo:-ghcr.io/openctemio/sensor}:$1${variant}"
}

check_version() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "a release is vX.Y.Z, got '$1'"
}

# The seccomp profile comes from the signed image itself, so it always
# matches the release that runs (no separate download to trust).
fetch_seccomp() { # fetch_seccomp VERSION
  local out="seccomp/sensor-$1.json" tmp
  [[ -s "$out" ]] && return 0
  mkdir -p seccomp
  tmp="$(mktemp seccomp/.profile.XXXXXX)"
  if ! docker run --rm --network none "$(image_ref "$1")" seccomp-profile >"$tmp" 2>/dev/null; then
    # Releases before v0.27.0 have no seccomp-profile command: the
    # profile of the same tag from the repository.
    curl -fsSL -o "$tmp" "https://raw.githubusercontent.com/openctemio/sensor/$1/docker/seccomp/sensor.json" || {
      rm -f "$tmp"
      die "could not get the seccomp profile of $1"
    }
  fi
  grep -q '"defaultAction"' "$tmp" || { rm -f "$tmp"; die "the seccomp profile of $1 is not a seccomp profile"; }
  chmod 0644 "$tmp"
  mv "$tmp" "$out"
  echo "seccomp profile: $out"
}

verify_image() { # verify_image VERSION: keyless cosign check of the release image
  local ref
  ref="$(image_ref "$1")"
  local args=(verify "$ref" --certificate-oidc-issuer "$OIDC_ISSUER"
    --certificate-identity "${IDENTITY_WORKFLOW}@refs/tags/$1")
  if command -v cosign >/dev/null 2>&1; then
    cosign "${args[@]}" >/dev/null
  else
    docker run --rm "$COSIGN_IMAGE" "${args[@]}" >/dev/null
  fi
  echo "signature verified: $ref"
}

ensure_sections() { # the three sections, once, at the end of compose.yaml
  grep -qxF "$MARK_SERVICES" compose.yaml && return 0
  grep -qE '^(services|volumes|networks):' compose.yaml &&
    die "compose.yaml has a services, volumes or networks section without the sensors.sh markers; add the sensor by hand"
  printf '\nservices:\n%s\n\nvolumes:\n%s\n\nnetworks:\n%s\n' \
    "$MARK_SERVICES" "$MARK_VOLUMES" "$MARK_NETWORKS" >>compose.yaml
}

insert_before() { # insert_before MARKER TEXT: TEXT goes on the lines above MARKER
  local tmp
  tmp="$(mktemp compose.yaml.XXXXXX)"
  MARK="$1" TEXT="$2" awk '$0 == ENVIRON["MARK"] { print ENVIRON["TEXT"] } { print }' compose.yaml >"$tmp"
  cat "$tmp" >compose.yaml
  rm -f "$tmp"
}

cmd_add() {
  local name="${1:-}" api_url="" code=""
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --api-url) api_url="${2:-}"; shift ;;
      --pairing-code) code="${2:-}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  # The name becomes a service, a volume, a network and a directory.
  [[ "$name" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || die "NAME: lowercase letters, digits and -, starting with a letter (at most 31)"
  [[ -z "$code" || "$code" =~ ^[A-Z0-9]{4}-[A-Z0-9]{4}$ ]] || die "--pairing-code is XXXX-XXXX"
  [[ -z "$api_url" || "$api_url" =~ ^https?://[^[:space:]]+$ ]] || die "--api-url is an http(s) URL"
  [[ -e "sensors/$name" ]] && die "sensors/$name exists: pick another name"
  grep -qE "^  ${name}(-data)?:" compose.yaml && die "compose.yaml already has $name"
  env_value SENSOR_VERSION >/dev/null

  ensure_sections
  local backup
  backup="$(mktemp compose.yaml.bak.XXXXXX)"
  cp compose.yaml "$backup"

  # Owner-only: the env file holds the pairing code (or a key).
  (umask 077 && mkdir -p "sensors/$name")
  mkdir -m 0755 "sensors/$name/policy"
  (
    umask 077
    cat >"sensors/$name/sensor.env" <<EOF
# Sensor "$name": read by docker compose for this service only.
SENSOR_API_URL=${api_url:-https://openctem.example.com}
SENSOR_NAME=$name
# Single use, valid 10 minutes, ignored once the sensor is paired: delete
# the line after the first start. Empty: the sensor prints a code to enter
# under Discovery > Sensors > Pair a sensor.
SENSOR_PAIRING_CODE=$code
# Private platform CA: mount it in this sensor's block and point at it.
# SENSOR_CA_CERT_FILE=/etc/openctem/policy/platform-ca.pem
# HTTPS_PROXY=http://proxy.example.com:3128
EOF
  )
  # Fail closed: an empty allow list allows nothing until the network owner
  # lists what this sensor may scan (docs/LOCAL_POLICY.md).
  cat >"sensors/$name/policy/sensor-policy.yaml" <<'EOF'
# Sensor-local policy of this sensor (docs/LOCAL_POLICY.md in openctemio/sensor).
# The network owner lists what it may scan; the sensor refuses every job
# outside it, whatever the platform sends. Restart the sensor after a change:
#   docker compose restart <name>
apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: []        # e.g. [203.0.113.0/24, "*.example.com"]; [] allows nothing
EOF
  chmod 0644 "sensors/$name/policy/sensor-policy.yaml"

  insert_before "$MARK_SERVICES" "  ${name}:
    <<: *sensor
    env_file: [sensors/${name}/sensor.env]
    volumes:
      - ${name}-data:/var/lib/openctem
      - ./sensors/${name}/policy:/etc/openctem/policy:ro
    networks: [${name}]
"
  insert_before "$MARK_VOLUMES" "  ${name}-data: {}"
  insert_before "$MARK_NETWORKS" "  ${name}: *network"

  if ! docker compose config -q; then
    cp "$backup" compose.yaml
    rm -f "$backup"
    rm -rf "sensors/$name"
    die "the new compose.yaml did not validate; nothing was changed"
  fi
  rm -f "$backup"
  cat <<EOF
Added sensor "$name":
  sensors/$name/sensor.env                   platform URL and pairing code (0600)
  sensors/$name/policy/sensor-policy.yaml    list what it may scan (allows nothing yet)
Then: ./sensors.sh up && ./sensors.sh logs $name
EOF
}

cmd_up() {
  local v
  v="$(env_value SENSOR_VERSION)"
  check_version "$v"
  fetch_seccomp "$v"
  docker compose up -d --remove-orphans
}

cmd_upgrade() {
  local v="${1:-}" old
  check_version "$v"
  old="$(env_value SENSOR_VERSION)"
  verify_image "$v"
  docker pull -q "$(image_ref "$v")" >/dev/null
  fetch_seccomp "$v"
  sed -i "s/^SENSOR_VERSION=.*/SENSOR_VERSION=$v/" .env
  echo "SENSOR_VERSION: $old -> $v"
  # Identity, outbox and content cache stay on each sensor's volume: no
  # sensor pairs again.
  docker compose up -d --remove-orphans
}

cmd_status() {
  docker compose ps
  local s
  for s in $(docker compose config --services); do
    printf '%-24s %s\n' "$s" "$(docker compose logs --no-log-prefix --tail 400 "$s" 2>/dev/null |
      grep -E 'Preflight:|Tool network:|pairing|Paired|paired' | tail -1 | cut -c1-110)"
  done
}

case "${1:-}" in
  add) shift; cmd_add "$@" ;;
  up) cmd_up ;;
  upgrade) shift; cmd_upgrade "$@" ;;
  status) cmd_status ;;
  logs) [[ -n "${2:-}" ]] || usage; docker compose logs -f --tail 100 "$2" ;;
  *) usage ;;
esac
