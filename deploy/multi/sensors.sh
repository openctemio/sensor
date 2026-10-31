#!/usr/bin/env bash
# sensors.sh: run several OpenCTEM sensors on one host from this directory
# (README.md). Every sensor has its own env file, data volume, network and
# policy directory; compose.yaml holds the shared hardened settings.
#
#   ./sensors.sh add NAME --api-url URL [--ca-sha256 HEX[,HEX] | --ca-file FILE] [--pairing-code XXXX-XXXX] [--no-start]
#                                   add one sensor, start it and pair it: it prints a link to open
#                                   in the console (pick its fingerprint, approve); ends once paired
#   ./sensors.sh pair NAME [--pairing-code XXXX-XXXX]
#                                   start one sensor (with a new code: write it, recreate the
#                                   container), show its code, link and fingerprint, wait for approval
#   ./sensors.sh repair NAME --pairing-code XXXX-XXXX [--yes]
#                                   the console's Re-pair: replace that sensor's key (identity only; the
#                                   outbox stays), then pair it with the code
#   ./sensors.sh set-ca NAME (--sha256 HEX[,HEX] | --file FILE)
#                                   platform behind a private certificate authority: pin its root CA by
#                                   SHA-256 (the sensor fetches the CA itself) or give the CA file; the
#                                   container is recreated
#   ./sensors.sh remove NAME [--purge] [--yes]
#                                   stop and remove one sensor; --purge also deletes its data volume
#   ./sensors.sh stop NAME | start NAME
#                                   stop or start one sensor (its key and outbox stay)
#   ./sensors.sh down               stop every sensor, remove the containers (volumes stay: never -v)
#   ./sensors.sh up                 fetch the release's seccomp profile, start every sensor
#   ./sensors.sh upgrade [--self-update] vX.Y.Z
#                                   verify the image signature, then move every sensor to it
#   ./sensors.sh self-update vX.Y.Z replace this kit's own files (sensors.sh, compose.yaml, README.md,
#                                   .env.example) with the release's, signature and checksums verified;
#                                   your sensors, volumes and sensors/ stay
#   ./sensors.sh status             one plain line per sensor: paired, waiting (with its link), or why not
#   ./sensors.sh logs NAME          follow one sensor's log
set -euo pipefail

cd "$(dirname "$0")"

die() { echo "sensors.sh: $*" >&2; exit 1; }
usage() { sed -n '2,31s/^# \{0,1\}//p' "$0"; exit 2; }

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

normalize_pins() { # normalize_pins HEX[,HEX]: lowercase hex without colons, comma separated
  local out="" p
  local IFS=,
  for p in $1; do
    p="${p//[: ]/}"
    p="$(tr 'A-F' 'a-f' <<<"$p")"
    [[ "$p" =~ ^[0-9a-f]{64}$ ]] || return 1
    out="${out:+$out,}$p"
  done
  [[ -n "$out" ]] || return 1
  echo "$out"
}

# set_env_key NAME KEY VALUE: set KEY in the sensor's env file. An active
# line is replaced, else the first commented example, else it is appended.
# Owner-only (0600), written beside the file and moved over it.
set_env_key() {
  local env="sensors/$1/sensor.env" tmp pat
  tmp="$(mktemp "sensors/$1/.sensor.env.XXXXXX")"
  chmod 0600 "$tmp"
  if grep -qE "^$2=" "$env"; then
    pat="$2="
  elif grep -qE "^# $2=" "$env"; then
    pat="# $2="
  else
    { cat "$env"; echo "$2=$3"; } >"$tmp"
    mv "$tmp" "$env"
    return 0
  fi
  PAT="$pat" LINE="$2=$3" awk '
    index($0, ENVIRON["PAT"]) == 1 { if (!done) print ENVIRON["LINE"]; done = 1; next }
    { print }' "$env" >"$tmp"
  mv "$tmp" "$env"
}

# show_ca_certs FILE: subject and SHA-256 of every certificate in a PEM file.
# The SHA-256 is of the certificate's DER bytes, the value to pin.
show_ca_certs() {
  local file="$1" dir f sum subj
  dir="$(mktemp -d)"
  awk -v d="$dir" '
    /-----BEGIN CERTIFICATE-----/ { n++; out = sprintf("%s/c%03d.b64", d, n); next }
    /-----END CERTIFICATE-----/ { out = ""; next }
    out != "" { print > out }' "$file"
  for f in "$dir"/c*.b64; do
    [[ -e "$f" ]] || continue
    sum="$(base64 -d "$f" 2>/dev/null | sha256sum | cut -d' ' -f1)"
    subj="(subject unavailable: openssl not installed)"
    if command -v openssl >/dev/null 2>&1; then
      subj="$({ echo "-----BEGIN CERTIFICATE-----"; cat "$f"; echo "-----END CERTIFICATE-----"; } |
        openssl x509 -noout -subject 2>/dev/null | sed 's/^subject= *//' || true)"
      [[ -n "$subj" ]] || subj="(not a readable certificate)"
    fi
    echo "  certificate $(basename "$f" .b64 | sed 's/^c0*//'): $subj"
    echo "    SHA-256: $sum"
  done
  find "$dir" -delete
  echo "  Compare the fingerprint of the ROOT certificate with the one the console shows under the install command."
}

check_ca_pem() { # check_ca_pem FLAG FILE: a readable file with PEM certificates, every one parsing when openssl is here
  local flag="$1" file="$2"
  [[ -f "$file" && -r "$file" ]] || die "$flag $file: not a readable file"
  grep -q -- '-----BEGIN CERTIFICATE-----' "$file" || die "$flag $file: not a PEM certificate"
}

cmd_add() {
  local name="${1:-}" api_url="" code="" ca_file="" ca_sha="" start=1
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --api-url) api_url="${2:-}"; shift ;;
      --pairing-code) code="${2:-}"; shift ;;
      --ca-file) ca_file="${2:-}"; shift ;;
      --ca-sha256) ca_sha="${2:-}"; shift ;;
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
  [[ -z "$ca_file" ]] || check_ca_pem --ca-file "$ca_file"
  if [[ -n "$ca_sha" ]]; then
    ca_sha="$(normalize_pins "$ca_sha")" || die "--ca-sha256 is 64 hex digits (colons allowed), several separated by commas"
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
  local sha_line="# SENSOR_CA_SHA256=<sha256 of the platform's root CA, hex>"
  [[ -z "$ca_sha" ]] || sha_line="SENSOR_CA_SHA256=$ca_sha"
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
# The platform's private certificate authority, if it has one. Either pin
# its ROOT by SHA-256 (the sensor fetches the CA from the platform and
# accepts only a certificate with this hash; comma-separated list for a
# rotation) or give the CA file. ./sensors.sh set-ca changes them later.
$sha_line
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
  if [[ -n "$ca_file" ]]; then
    echo "Private CA file installed (sensors/$name/policy/platform-ca.pem); it holds:"
    show_ca_certs "$ca_file"
  fi
  [[ -z "$ca_sha" ]] || echo "Private CA pinned: SENSOR_CA_SHA256=$ca_sha"
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
        echo "  The platform uses a private certificate authority. Pin its ROOT (the SHA-256 the console shows under"
        echo "  the install command; the message above lists every certificate the platform presented):"
        echo "    ./sensors.sh set-ca $name --sha256 HEX      (or --file FILE with the CA in PEM)"
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

cmd_set_ca() { # set-ca NAME (--sha256 HEX[,HEX] | --file FILE): trust the platform's private CA
  local name="${1:-}" sha="" file=""
  [[ -n "$name" ]] || usage
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sha256) sha="${2:-}"; shift ;;
      --file) file="${2:-}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_sensor "$name"
  [[ -n "$sha" || -n "$file" ]] || die "set-ca needs --sha256 HEX (the root CA's fingerprint) or --file FILE (the CA in PEM)"
  [[ -z "$sha" || -z "$file" ]] || die "set-ca takes --sha256 or --file, not both"
  if [[ -n "$sha" ]]; then
    sha="$(normalize_pins "$sha")" || die "--sha256 is 64 hex digits (colons allowed), several separated by commas"
    set_env_key "$name" SENSOR_CA_SHA256 "$sha"
    echo "Pinned the platform's root CA for $name: SENSOR_CA_SHA256=$sha (sensors/$name/sensor.env)."
    echo "The sensor fetches the CA from the platform and accepts it only if a certificate in it has this hash."
  else
    check_ca_pem --file "$file"
    if command -v openssl >/dev/null 2>&1; then
      local d
      d="$(mktemp -d)"
      awk -v d="$d" '/-----BEGIN CERTIFICATE-----/ { n++; out = sprintf("%s/c%03d.pem", d, n) } out != "" { print > out } /-----END CERTIFICATE-----/ { out = "" }' "$file"
      for f in "$d"/c*.pem; do
        openssl x509 -noout -in "$f" 2>/dev/null || { find "$d" -delete; die "--file $file: a certificate in it does not parse"; }
      done
      find "$d" -delete
    fi
    mkdir -p "sensors/$name/policy"
    install -m 0644 "$file" "sensors/$name/policy/platform-ca.pem"
    set_env_key "$name" SENSOR_CA_CERT_FILE /etc/openctem/policy/platform-ca.pem
    echo "Installed sensors/$name/policy/platform-ca.pem (mode 0644); it holds:"
    show_ca_certs "$file"
  fi
  docker compose up -d --force-recreate "$name"
  echo "Recreated $name. Check with: ./sensors.sh status   (the line says running and paired, or why not)"
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

RELEASE_WORKFLOW="https://github.com/openctemio/sensor/.github/workflows/release.yml"
# Where a release's kit files are downloaded from. Only for tests: another
# https:// base or a file:// directory. The signature is verified whatever
# the base is, so a different base cannot get unsigned files accepted.
RELEASE_BASE="${SENSORS_RELEASE_BASE:-https://github.com/openctemio/sensor/releases/download}"
KIT_FILES=(sensors.sh compose.yaml README.md .env.example)

kit_remote_name() { local f="${1#.}"; echo "deploy-multi-$f"; } # .env.example -> deploy-multi-env.example

kit_fetch() { # kit_fetch URL OUT
  curl -fsSL --proto '=https,file' --max-time 120 -o "$2" "$1" || die "could not download $1"
}

kit_verify_sums() { # kit_verify_sums DIR VERSION: keyless cosign check of the release's kit checksums
  local dir="$1" args
  args=(verify-blob "$dir/deploy-multi.SHA256SUMS" --bundle "$dir/deploy-multi.SHA256SUMS.sigstore.json"
    --certificate-oidc-issuer "$OIDC_ISSUER"
    --certificate-identity "${RELEASE_WORKFLOW}@refs/tags/$2")
  if command -v cosign >/dev/null 2>&1; then
    cosign "${args[@]}" >/dev/null 2>&1 || die "the signature of $2's kit checksums did not verify; nothing was changed"
  else
    args=("${args[@]//$dir//w}")
    docker run --rm -v "$dir:/w:ro" "$COSIGN_IMAGE" "${args[@]}" >/dev/null 2>&1 ||
      die "the signature of $2's kit checksums did not verify; nothing was changed"
  fi
  echo "signature verified: $2 kit checksums"
}

cmd_self_update() { # self-update vX.Y.Z: this kit's files from the signed release, sensors untouched
  local v="${1:-}" tmp f ts base
  check_version "$v"
  case "$RELEASE_BASE" in
    https://* | file://*) ;;
    *) die "SENSORS_RELEASE_BASE must be an https:// URL" ;;
  esac
  base="$RELEASE_BASE/$v"
  tmp="$(mktemp -d ./.self-update.XXXXXX)"
  tmp="$(cd "$tmp" && pwd)"
  KIT_TMP="$tmp"
  trap 'find "$KIT_TMP" -delete 2>/dev/null || true' EXIT
  kit_fetch "$base/deploy-multi.SHA256SUMS" "$tmp/deploy-multi.SHA256SUMS"
  kit_fetch "$base/deploy-multi.SHA256SUMS.sigstore.json" "$tmp/deploy-multi.SHA256SUMS.sigstore.json"
  kit_verify_sums "$tmp" "$v" || { find "$tmp" -delete; exit 1; }
  for f in "${KIT_FILES[@]}"; do
    grep -qF " $(kit_remote_name "$f")" "$tmp/deploy-multi.SHA256SUMS" ||
      { find "$tmp" -delete; die "$v's signed checksums do not list $f; nothing was changed"; }
    kit_fetch "$base/$(kit_remote_name "$f")" "$tmp/$(kit_remote_name "$f")"
  done
  (cd "$tmp" && sha256sum -c --quiet deploy-multi.SHA256SUMS) >/dev/null 2>&1 ||
    { find "$tmp" -delete; die "a downloaded file does not match $v's signed checksums; nothing was changed"; }
  f="$tmp/$(kit_remote_name compose.yaml)"
  if grep -q '^services:' "$f"; then find "$tmp" -delete; die "$v's compose.yaml already has a services section; nothing was changed"; fi
  head -1 "$tmp/$(kit_remote_name sensors.sh)" | grep -q '^#!/usr/bin/env bash' ||
    { find "$tmp" -delete; die "$v's sensors.sh is not a bash script; nothing was changed"; }

  # New template, then the existing services, volumes and networks sections
  # (your sensors and anything you changed in their blocks) from `services:` on.
  { cat "$f"; if grep -q '^services:' compose.yaml; then echo; awk '/^services:/ { on = 1 } on' compose.yaml; fi; } >"$tmp/compose.merged"

  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  for f in "${KIT_FILES[@]}"; do
    [[ -e "$f" ]] && cp -p "$f" "$f.bak-$ts"
  done
  install -m 0644 "$tmp/compose.merged" compose.yaml
  install -m 0644 "$tmp/$(kit_remote_name README.md)" README.md
  install -m 0644 "$tmp/$(kit_remote_name .env.example)" .env.example
  if ! docker compose config -q; then
    for f in compose.yaml README.md .env.example; do
      [[ -e "$f.bak-$ts" ]] && mv "$f.bak-$ts" "$f"
    done
    rm -f "sensors.sh.bak-$ts"
    find "$tmp" -delete
    die "the updated compose.yaml did not validate; every file is back as it was"
  fi
  echo "Updated to the $v kit (backups: <file>.bak-$ts):"
  for f in compose.yaml README.md .env.example; do
    [[ -e "$f.bak-$ts" ]] || continue
    echo "  $f: $(diff -u "$f.bak-$ts" "$f" | grep -c '^+[^+]') lines added, $(diff -u "$f.bak-$ts" "$f" | grep -c '^-[^-]') removed"
  done
  # The script is replaced last, by a new file moved over it: this run keeps reading the old one.
  install -m 0755 "$tmp/$(kit_remote_name sensors.sh)" "$tmp/sensors.sh.new"
  mv "$tmp/sensors.sh.new" sensors.sh
  echo "  sensors.sh: replaced"
  find "$tmp" -delete
  # A sensor that narrowed itself through the old kit's policy file keeps
  # doing so only when its env file names the file.
  for f in sensors/*/policy/sensor-policy.yaml; do
    [[ -e "$f" ]] || continue
    if grep -qE '^[[:space:]]*allow:' "$f" && ! grep -qE '^SENSOR_LOCAL_POLICY=' "$(dirname "$(dirname "$f")")/sensor.env"; then
      echo "NOTE: $f narrows scope, but the sensor no longer reads it by default. To keep it, add"
      echo "      SENSOR_LOCAL_POLICY=/etc/openctem/policy/sensor-policy.yaml to $(dirname "$(dirname "$f")")/sensor.env, then ./sensors.sh up."
    fi
  done
  echo "Sensors, volumes and sensors/ were not touched. Recreate the sensors with the new file: ./sensors.sh up"
}

cmd_upgrade() {
  local v="" old self=0 a
  for a in "$@"; do
    case "$a" in
      --self-update) self=1 ;;
      *) v="$a" ;;
    esac
  done
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
  if [[ "$self" == 0 ]] && legacy_policy_anchor; then
    # This kit's compose.yaml still hard-wires a local policy file, so a
    # sensor never follows the platform's scope alone and needs that file.
    if [[ -t 0 ]]; then
      local answer=""
      read -r -p "This kit's compose.yaml is out of date (it requires a policy file per sensor). Update the kit files to $v too? [y/N] " answer || true
      [[ "$answer" == y || "$answer" == Y || "$answer" == yes ]] && self=1
    else
      echo "This kit's compose.yaml is out of date: ./sensors.sh self-update $v (or upgrade --self-update $v) replaces it."
    fi
  fi
  [[ "$self" == 0 ]] || cmd_self_update "$v"
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
    *"does not trust"*) echo "cannot reach the platform: its certificate authority is not trusted (./sensors.sh set-ca $s --sha256 HEX, or --file FILE)" ;;
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
  set-ca) shift; cmd_set_ca "$@" ;;
  repair) shift; cmd_repair "$@" ;;
  remove) shift; cmd_remove "$@" ;;
  stop) shift; cmd_stop "${1:-}" ;;
  start) shift; cmd_start "${1:-}" ;;
  down) cmd_down ;;
  up) cmd_up ;;
  self-update) shift; cmd_self_update "${1:-}" ;;
  upgrade) shift; cmd_upgrade "$@" ;;
  status) cmd_status ;;
  logs) [[ -n "${2:-}" ]] || usage; docker compose logs -f --tail 100 "$2" ;;
  *) usage ;;
esac
