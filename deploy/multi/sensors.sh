#!/usr/bin/env bash
# sensors.sh: run several OpenCTEM sensors on one host from this directory
# (README.md). Every sensor has its own env file, data volume, network and
# policy directory; compose.yaml holds the shared hardened settings.
#
#   ./sensors.sh add NAME --api-url URL [--ca-file FILE] [--pairing-code XXXX-XXXX] [--no-start]
#                                   add one sensor, start it and pair it: it prints a link to open
#                                   in the console (pick its fingerprint, approve); ends once paired
#   ./sensors.sh pair NAME [--pairing-code XXXX-XXXX]
#                                   start one sensor (with a new code: write it, recreate the
#                                   container), show its code, link and fingerprint, wait for approval
#   ./sensors.sh repair NAME --pairing-code XXXX-XXXX [--yes]
#                                   the console's Re-pair: replace that sensor's key (identity only; the
#                                   outbox stays), then pair it with the code
#   ./sensors.sh remove NAME [--purge] [--yes]
#                                   stop and remove one sensor; --purge also deletes its data volume
#   ./sensors.sh stop NAME | start NAME
#                                   stop or start one sensor (its key and outbox stay)
#   ./sensors.sh down               stop every sensor, remove the containers (volumes stay: never -v)
#   ./sensors.sh up                 fetch the release's seccomp profile, start every sensor
#   ./sensors.sh upgrade vX.Y.Z     verify the image signature, then move every sensor to it
#   ./sensors.sh status             one plain line per sensor: paired, waiting (with its link), or why not
#   ./sensors.sh logs NAME          follow one sensor's log
set -euo pipefail

cd "$(dirname "$0")"

die() { echo "sensors.sh: $*" >&2; exit 1; }
usage() { sed -n '2,24s/^# \{0,1\}//p' "$0"; exit 2; }

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

# An older kit's compose.yaml makes every sensor read a local policy file
# (SENSOR_LOCAL_POLICY in x-sensor), so a sensor without one does not start.
legacy_policy_anchor() { grep -qE '^    SENSOR_LOCAL_POLICY:' compose.yaml; }

cmd_add() {
  local name="${1:-}" api_url="" code="" ca_file="" start=1
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --api-url) api_url="${2:-}"; shift ;;
      --pairing-code) code="${2:-}"; shift ;;
      --ca-file) ca_file="${2:-}"; shift ;;
      --no-start) start=0 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  # The name becomes a service, a volume, a network and a directory.
  [[ "$name" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || die "NAME: lowercase letters, digits and -, starting with a letter (at most 31)"
  [[ -z "$code" || "$code" =~ ^[A-Z0-9]{4}-[A-Z0-9]{4}$ ]] || die "--pairing-code is XXXX-XXXX"
  [[ -z "$api_url" || "$api_url" =~ ^https?://[^[:space:]]+$ ]] || die "--api-url is an http(s) URL"
  [[ -n "$api_url" || "$start" == 0 ]] ||
    die "--api-url is the platform's address (the one you sign in to), e.g. --api-url https://openctem.example.com"
  if [[ -n "$ca_file" ]]; then
    [[ -f "$ca_file" && -r "$ca_file" ]] || die "--ca-file $ca_file: not a readable file"
    grep -q -- '-----BEGIN CERTIFICATE-----' "$ca_file" || die "--ca-file $ca_file: not a PEM certificate"
  fi
  # https://host/ and https://host are the same platform; the sensor joins
  # paths to it, so keep one form.
  while [[ "$api_url" == */ ]]; do api_url="${api_url%/}"; done
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
  local ca_line="# SENSOR_CA_CERT_FILE=/etc/openctem/policy/platform-ca.pem"
  if [[ -n "$ca_file" ]]; then
    install -m 0644 "$ca_file" "sensors/$name/policy/platform-ca.pem"
    ca_line="SENSOR_CA_CERT_FILE=/etc/openctem/policy/platform-ca.pem"
  fi
  (
    umask 077
    cat >"sensors/$name/sensor.env" <<ENVFILE
# Sensor "$name": read by docker compose for this service only.
SENSOR_API_URL=${api_url:-https://openctem.example.com}
SENSOR_NAME=$name
# Single use; sensors.sh clears it once the sensor is paired. Empty: the
# sensor prints its own code and a link to approve it on.
SENSOR_PAIRING_CODE=$code
# The platform's private certificate authority (--ca-file), if it has one.
$ca_line
# Narrow what this sensor may scan on this host (optional): write
# sensors/$name/policy/sensor-policy.yaml (it can only narrow), uncomment
# the next line, then ./sensors.sh stop $name and ./sensors.sh start $name.
# Without it the sensor follows your organization's scope.
# SENSOR_LOCAL_POLICY=/etc/openctem/policy/sensor-policy.yaml
# HTTPS_PROXY=http://proxy.example.com:3128
ENVFILE
  )
  if legacy_policy_anchor; then
    # This directory's compose.yaml needs the file to exist. It narrows
    # nothing: without targets.allow the sensor follows the platform's scope.
    cat >"sensors/$name/policy/sensor-policy.yaml" <<'POLICY'
# Sensor-local policy of this sensor (docs/LOCAL_POLICY.md in openctemio/sensor).
# Optional and narrow-only. Without a targets.allow list the sensor follows
# the platform's signed scope. List ranges or domains here only to narrow it:
# the sensor then refuses every job outside the list, whatever the platform
# sends. An empty list (allow: []) allows nothing.
apiVersion: openctem.io/sensor-policy/v1
# targets:
#   allow:
#     - 203.0.113.0/24
#     - "*.example.com"
POLICY
    chmod 0644 "sensors/$name/policy/sensor-policy.yaml"
  fi

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
  echo "Added sensor \"$name\" (settings in sensors/$name/sensor.env, mode 0600)."
  if legacy_policy_anchor; then
    echo "This directory's compose.yaml reads a local policy file for every sensor: sensors/$name/policy/sensor-policy.yaml narrows nothing until you list ranges in it."
  fi
  if [[ "$start" == 0 ]]; then
    echo "Then: ./sensors.sh pair $name   (starts it, shows its code, link and fingerprint, waits for approval)"
    return 0
  fi
  cmd_pair "$name"
}

# How long `pair` waits: a pairing request lives 10 minutes and the sensor
# starts a new one when it expires.
PAIR_WAIT_SECONDS="${PAIR_WAIT_SECONDS:-900}"
# How long pulling a missing image may take before `pair` gives up with a hint.
PULL_TIMEOUT_SECONDS="${PULL_TIMEOUT_SECONDS:-600}"

set_pairing_code() { # set_pairing_code NAME CODE: the code the sensor starts with
  local env="sensors/$1/sensor.env" tmp
  tmp="$(mktemp "sensors/$1/.sensor.env.XXXXXX")"
  chmod 0600 "$tmp"
  if grep -qE '^SENSOR_PAIRING_CODE=' "$env"; then
    sed "s/^SENSOR_PAIRING_CODE=.*/SENSOR_PAIRING_CODE=$2/" "$env" >"$tmp"
  else
    { cat "$env"; echo "SENSOR_PAIRING_CODE=$2"; } >"$tmp"
  fi
  mv "$tmp" "$env"
  echo "Wrote the pairing code to $env."
}

pull_image() { # pull_image NAME: pull the sensor's image, with progress, when it is not here yet
  local img rc=0
  img="$(docker compose config --images "$1" | head -1)"
  [[ -n "$img" ]] || die "compose.yaml names no image for $1"
  docker image inspect "$img" >/dev/null 2>&1 && return 0
  echo "Pulling $img (up to $((PULL_TIMEOUT_SECONDS / 60)) minutes)..."
  timeout "$PULL_TIMEOUT_SECONDS" docker compose pull "$1" || rc=$?
  case "$rc" in
    0) ;;
    124) die "pulling $img did not finish in $((PULL_TIMEOUT_SECONDS / 60)) minutes. A pull stopped with Ctrl-C can leave a stale download behind that makes the next pull hang: restart the container runtime (sudo systemctl restart containerd docker), then run pair again" ;;
    *) die "pulling $img failed (exit $rc); check the network, the registry and SENSOR_VERSION in .env" ;;
  esac
}

cmd_pair() { # pair NAME [--pairing-code CODE]: start one sensor and follow its pairing until approved
  local name="${1:-}" v line paired=0 pid code=""
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-code) code="${2:-}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  [[ "$name" =~ ^[a-z][a-z0-9-]{0,30}$ && -f "sensors/$name/sensor.env" ]] ||
    die "no sensor named '$name' here (./sensors.sh add $name first)"
  [[ -z "$code" || "$code" =~ ^[A-Z0-9]{4}-[A-Z0-9]{4}$ ]] || die "--pairing-code is XXXX-XXXX"
  [[ "$PAIR_WAIT_SECONDS" =~ ^[0-9]+$ ]] || die "PAIR_WAIT_SECONDS is a number of seconds"
  [[ "$PULL_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || die "PULL_TIMEOUT_SECONDS is a number of seconds"
  v="$(env_value SENSOR_VERSION)"
  check_version "$v"
  fetch_seccomp "$v"
  pull_image "$name"
  if [[ -n "$code" ]]; then
    # The sensor reads its env file when the container is created: a new
    # code needs a new container. Its key stays on its volume, and the
    # platform lets a key that was never approved start again.
    set_pairing_code "$name" "$code"
    docker compose up -d --force-recreate "$name"
  else
    docker compose up -d "$name"
  fi
  # Ctrl-C stops the waiting only: say so, and how to come back.
  trap 'echo; echo "Stopped waiting: $name keeps running. Approve it in the console, then run ./sensors.sh pair $name again to watch."; exit 130' INT
  echo "Waiting for $name to pair (up to $((PAIR_WAIT_SECONDS / 60)) minutes; Ctrl-C stops waiting, the sensor keeps running)."
  echo "Open the link it prints (signed in to the console), check the organization, pick the fingerprint shown here, approve."
  # Only the lines that matter to the person approving: the code, the
  # fingerprint, the key, warnings and the outcome.
  exec 3< <(timeout "$PAIR_WAIT_SECONDS" docker compose logs -f --no-log-prefix --tail 200 "$name" 2>&1)
  pid=$!
  while IFS= read -r line <&3; do
    case "$line" in
      *"Paired:"* | *"Enrolled:"* | *"Preflight: "*)
        # Preflight without a pairing: it was paired earlier and went
        # straight to its checks.
        echo "  $line"
        paired=1
        break
        ;;
      *"already registered"*)
        # The platform approved this key once: it never pairs again.
        echo "  $line"
        echo "  This sensor's key was approved before and cannot pair again. Restore its identity, or remove its key"
        echo "  (the identity directory on the ${name}-data volume) so it makes a new one, then:"
        echo "    ./sensors.sh pair $name --pairing-code NEW-CODE"
        break
        ;;
      *"does not trust"*)
        # A private certificate authority, or TLS interception: no retry fixes it.
        echo "  $line"
        echo "  Give the sensor the platform's certificate authority (compare its SHA-256 with the one the console"
        echo "  shows under the install command): ./sensors.sh remove $name --yes, then add it again with --ca-file FILE."
        break
        ;;
      *"pairing-key-busy"* | *"HTTP 409"*)
        echo "  $line"
        echo "  Another pairing request holds this sensor's key. Make a new code in the console, then:"
        echo "    ./sensors.sh pair $name --pairing-code NEW-CODE"
        ;;
      *"Pair this sensor"* | *"Code:"* | *"Fingerprint:"* | *"Key:"* | *"Attached to pairing code"* | \
        *"pick this fingerprint"* | *"was refused"* | *"Pairing refused"* | *"Retrying in"* | *"clock"* | \
        *"Enrolling"* | *"expired"* | *"WARNING"* | *"Error"* | *"Rate limited"* | *"Pairing failed"*)
        echo "  $line"
        ;;
    esac
  done
  kill "$pid" 2>/dev/null || true
  exec 3<&-
  trap - INT
  [[ "$paired" == 1 ]] ||
    die "$name did not pair within $((PAIR_WAIT_SECONDS / 60)) minutes; ./sensors.sh logs $name shows why (run pair again to keep waiting)"
  # A pairing code is single use: clear it so it does not stay in the env file.
  if grep -qE '^SENSOR_PAIRING_CODE=.+' "sensors/$name/sensor.env"; then
    sed -i 's/^SENSOR_PAIRING_CODE=.*/SENSOR_PAIRING_CODE=/' "sensors/$name/sensor.env"
    echo "Cleared the spent pairing code from sensors/$name/sensor.env."
  fi
  echo "$name is paired and running. It follows your organization's scope; to narrow it on this host, see sensors/$name/sensor.env."
}

confirm() { # confirm YES_FLAG: ask unless --yes was given
  [[ "$1" == 1 ]] && return 0
  local answer=""
  [[ -t 0 ]] || die "not a terminal: pass --yes to go ahead"
  read -r -p "Continue? [y/N] " answer || true
  [[ "$answer" == y || "$answer" == Y || "$answer" == yes ]] || die "stopped; nothing was changed"
}

check_sensor() { # check_sensor NAME: a sensor of this directory
  [[ "$1" =~ ^[a-z][a-z0-9-]{0,30}$ && -f "sensors/$1/sensor.env" ]] ||
    die "no sensor named '$1' here"
}

compose_project() { sed -n 's/^name: *//p' compose.yaml | head -1 | tr -d '"'"'"; }

# A helper image with rm: the sensor images are distroless (no shell, no rm).
# Pinned by digest, the same base image the sensor builds from.
REPAIR_HELPER_IMAGE="${REPAIR_HELPER_IMAGE:-public.ecr.aws/docker/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587}"

# The uid:gid that owns the data volume: the one the sensor's image runs as.
service_user() { # service_user NAME
  local img u
  img="$(docker compose config --images "$1" | head -1)"
  u="$(docker image inspect -f '{{.Config.User}}' "$img" 2>/dev/null || true)"
  case "$u" in
    nonroot) echo 65532:65532 ;;
    [0-9]*:[0-9]*) echo "$u" ;;
    [0-9]*) echo "$u:$u" ;;
    *) echo 999:999 ;; # the image's own "openctem" user
  esac
}

# Delete ONLY the identity directory of a sensor's volume. The throwaway
# container has no network, a read-only root, no capabilities, runs as the
# volume's owner, and never sees the Docker socket. The outbox (and the
# content caches) are not touched: a re-pair keeps the sensor id, so results
# queued under the old key are still delivered under the new one.
wipe_identity() { # wipe_identity NAME
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --user "$(service_user "$1")" \
    --entrypoint rm -v "$(compose_project)_$1-data:/var/lib/openctem" \
    "$REPAIR_HELPER_IMAGE" -rf /var/lib/openctem/state/identity
}

cmd_repair() { # repair NAME --pairing-code CODE [--yes]
  local name="${1:-}" code="" yes=0
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-code) code="${2:-}"; shift ;;
      --yes) yes=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_sensor "$name"
  code="$(echo "$code" | tr '[:lower:]' '[:upper:]')"
  [[ "$code" =~ ^[0-9A-HJKMNP-TV-Z]{4}-?[0-9A-HJKMNP-TV-Z]{4}$ ]] ||
    die "--pairing-code is the code of the console's Re-pair, XXXX-XXXX"
  [[ "$code" == *-* ]] || code="${code:0:4}-${code:4}"
  echo "This replaces the key of $name. Its current key keeps working until you approve the re-pair in the console, unless you revoked it there."
  echo "Its name, zones, grant, queued results and caches stay; only the key is made again."
  confirm "$yes"
  docker compose stop "$name"
  wipe_identity "$name"
  echo "Removed the identity of $name from its volume (the outbox and caches are untouched)."
  cmd_pair "$name" --pairing-code "$code"
}

cmd_remove() { # remove NAME [--purge] [--yes]
  local name="${1:-}" purge=0 yes=0 proj tmp
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge) purge=1 ;;
      --yes) yes=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_sensor "$name"
  proj="$(compose_project)"
  echo "This stops $name and removes its container and sensors/$name/ (env file, policy)."
  if [[ "$purge" == 1 ]]; then
    echo "--purge also deletes its data volume ${proj}_${name}-data: its key and the results in its outbox that"
    echo "the platform has not accepted yet are lost; the sensor must be re-paired or added again."
  else
    echo "Its data volume ${proj}_${name}-data stays (key and outbox); --purge deletes it."
  fi
  confirm "$yes"
  docker compose rm -sf "$name"
  if [[ "$purge" == 1 ]]; then
    docker volume rm "${proj}_${name}-data"
    docker network rm "${proj}_${name}" >/dev/null 2>&1 || true
  fi
  # Drop the sensor's blocks from compose.yaml; put the file back when the
  # rest does not validate.
  tmp="$(mktemp compose.yaml.XXXXXX)"
  cp compose.yaml "$tmp"
  NAME="$name" awk '
    /^[a-z]/ { skipping = 0 }
    skipping && (/^    / || /^[[:space:]]*$/) { next }
    { skipping = 0 }
    $0 == "  " ENVIRON["NAME"] ":" || index($0, "  " ENVIRON["NAME"] ": ") == 1 ||
    $0 == "  " ENVIRON["NAME"] "-data:" || index($0, "  " ENVIRON["NAME"] "-data: ") == 1 { skipping = 1; next }
    { print }
  ' "$tmp" >compose.yaml
  if ! docker compose config -q; then
    cp "$tmp" compose.yaml
    rm -f "$tmp"
    die "compose.yaml without $name did not validate; compose.yaml was put back, sensors/$name was kept"
  fi
  rm -f "$tmp"
  rm -rf "sensors/$name"
  echo "Removed $name."
  echo "Also revoke or delete it in the console (Sensors > $name > Revoke access / Delete), so its key stops working there."
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
  # Show docker's own progress: a quiet pull looks like a hang.
  echo "Pulling $(image_ref "$v") (up to $((PULL_TIMEOUT_SECONDS / 60)) minutes)..."
  timeout "$PULL_TIMEOUT_SECONDS" docker pull "$(image_ref "$v")" ||
    die "pulling $(image_ref "$v") did not finish or failed; check the network and the registry, then run upgrade again"
  fetch_seccomp "$v"
  sed -i "s/^SENSOR_VERSION=.*/SENSOR_VERSION=$v/" .env
  echo "SENSOR_VERSION: $old -> $v"
  # Identity, outbox and content cache stay on each sensor's volume: no
  # sensor pairs again.
  docker compose up -d --remove-orphans
}

cmd_stop() { # stop NAME
  check_sensor "${1:-}"
  docker compose stop "$1"
  echo "Stopped $1 (its key and queued results stay). ./sensors.sh start $1 starts it again."
}

cmd_start() { # start NAME
  local v
  check_sensor "${1:-}"
  v="$(env_value SENSOR_VERSION)"
  check_version "$v"
  fetch_seccomp "$v"
  docker compose up -d "$1"
}

cmd_down() {
  # Never -v: the volumes hold every sensor's key and undelivered results.
  docker compose down --remove-orphans
  echo "Stopped every sensor and removed the containers; volumes (keys, queued results) stay. ./sensors.sh up starts them again."
}

# status_line NAME: one plain sentence for one sensor, from its container
# state and its own log.
status_line() {
  local s="$1" state logs last
  state="$(docker compose ps --all --format '{{.State}}' "$s" 2>/dev/null | head -1)"
  [[ -n "$state" ]] || { echo "not started (./sensors.sh start $s)"; return; }
  logs="$(docker compose logs --no-log-prefix --tail 400 "$s" 2>/dev/null || true)"
  if [[ "$state" != running ]]; then
    last="$(grep -E 'Error|refused|does not trust|Pairing' <<<"$logs" | tail -1 | cut -c1-90 || true)"
    echo "stopped ($state)${last:+: $last}"
    return
  fi
  last="$(grep -E 'Pair this sensor|Paired:|Enrolled:|Preflight:|does not trust|Pairing refused|was refused|Pairing failed' <<<"$logs" | tail -1 || true)"
  case "$last" in
    *"Pair this sensor: open "*) echo "waiting for approval: open ${last#*open }" ;;
    *"Pair this sensor"*) echo "waiting for approval: enter its code (./sensors.sh logs $s)" ;;
    *"does not trust"*) echo "cannot reach the platform: its certificate authority is not trusted (add it with --ca-file)" ;;
    *"Pairing refused"* | *"was refused"* | *"Pairing failed"*) echo "not paired: $(cut -c1-90 <<<"$last")" ;;
    "") echo "running" ;;
    *) echo "running and paired" ;;
  esac
}

cmd_status() {
  local s
  for s in $(docker compose config --services); do
    printf '%-24s %s\n' "$s" "$(status_line "$s")"
  done
}

case "${1:-}" in
  add) shift; cmd_add "$@" ;;
  pair) shift; cmd_pair "$@" ;;
  repair) shift; cmd_repair "$@" ;;
  remove) shift; cmd_remove "$@" ;;
  stop) shift; cmd_stop "${1:-}" ;;
  start) shift; cmd_start "${1:-}" ;;
  down) cmd_down ;;
  up) cmd_up ;;
  upgrade) shift; cmd_upgrade "$@" ;;
  status) cmd_status ;;
  logs) [[ -n "${2:-}" ]] || usage; docker compose logs -f --tail 100 "$2" ;;
  *) usage ;;
esac
