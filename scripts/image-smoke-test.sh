#!/usr/bin/env bash
# Smoke-test a built sensor image.
#
#   scripts/image-smoke-test.sh <variant> <image>
#
# Every tool the variant bundles must run (`<tool> --version` or its
# equivalent) and `openctemio-sensor -list-tools` must report it available.
# A tool that is shipped but broken (semgrep without pkg_resources, in the
# v0.3.0 images) fails the build here instead of being skipped silently by
# the sensor at run time. The "default" image is also checked to start the
# server-controlled daemon and to refuse, with an actionable error, to run
# without API_URL / API_KEY.
set -euo pipefail

variant="${1:?usage: image-smoke-test.sh <variant> <image>}"
image="${2:?usage: image-smoke-test.sh <variant> <image>}"

case "$variant" in
  # The default (platform) image also ships the recon tools (EASM discovery).
  default) tools="nuclei subfinder dnsx naabu httpx katana" ;;
  semgrep | betterleaks | trivy | nuclei) tools="$variant" ;;
  *)
    echo "unknown variant: $variant" >&2
    exit 2
    ;;
esac

# version_args prints the arguments that make a tool print its version.
version_args() {
  case "$1" in
    betterleaks) echo "version" ;;
    nuclei) echo "-version -disable-update-check" ;;
    subfinder | dnsx | naabu | httpx | katana) echo "-version -duc" ;;
    *) echo "--version" ;;
  esac
}

failed=0
fail() {
  echo "FAIL: $*" >&2
  failed=1
}

echo "== $image ($variant): $tools"

# Sensors are outbound-only (api RFC-040 §11.1): the image exposes no port.
exposed=$(docker image inspect --format '{{json .Config.ExposedPorts}}' "$image")
if [ "$exposed" != "null" ] && [ "$exposed" != "{}" ]; then
  fail "$image exposes ports $exposed; sensors accept no inbound connections"
else
  echo "  exposed ports: none"
fi

for tool in $tools; do
  # shellcheck disable=SC2046 # version_args is a word list on purpose
  if out=$(docker run --rm --entrypoint "$tool" "$image" $(version_args "$tool") 2>&1); then
    out=$(printf "%s\n" "$out" | sed "s/\x1b\[[0-9;]*m//g")
    ver=$(printf "%s\n" "$out" | grep -i "version" | head -n 1 || true)
    echo "  $tool: ${ver:-$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -n 1)}"
  else
    fail "$tool does not run in $image:"
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/    /' >&2
  fi
done

if ! list=$(docker run --rm --entrypoint openctemio-sensor "$image" -list-tools 2>&1); then
  fail "openctemio-sensor -list-tools failed:"
  printf '%s\n' "$list" | sed 's/^/    /' >&2
fi
for tool in $tools; do
  line=$(printf '%s\n' "$list" | grep -E "^[[:space:]]+${tool}[[:space:]]+- " | head -n 1 || true)
  if printf '%s\n' "$line" | grep -q '\[available: '; then
    echo "  -list-tools: $(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
  else
    fail "-list-tools does not report $tool available: ${line:-<no line>}"
  fi
done

# A server-controlled daemon given no tool list runs (and reports) every
# scanner installed in the image: the variant decides the tool set, nothing
# is declared on the platform. The platform here is unreachable on purpose;
# only the start-up line is checked.
want_tools=$(printf '%s\n' $tools | paste -sd, - | sed 's/,/, /g')
name="sensor-smoke-detect-$$"
docker run -d --name "$name" -e API_URL=http://127.0.0.1:9 -e API_KEY=smoke -e SENSOR_TOOLS= \
  --entrypoint openctemio-sensor "$image" -daemon -enable-commands >/dev/null
detected=""
for _ in $(seq 1 60); do
  detected=$(docker logs "$name" 2>&1 | grep -E '^[[:space:]]*Tools: ' | head -n 1 || true)
  [ -n "$detected" ] && break
  sleep 1
done
logs=$(docker logs "$name" 2>&1 || true)
docker rm -f "$name" >/dev/null 2>&1 || true
if printf '%s\n' "$detected" | grep -qF "Tools: $want_tools (detected"; then
  echo "  daemon without SENSOR_TOOLS: $(printf '%s' "$detected" | sed 's/^[[:space:]]*//')"
else
  fail "daemon without SENSOR_TOOLS did not detect '$want_tools': ${detected:-<no Tools line>}"
  printf '%s\n' "$logs" | tail -n 15 | sed 's/^/    /' >&2
fi

if [ "$variant" = default ] || [ "$variant" = nuclei ]; then
  # The baked nuclei-templates set (scripts/nuclei-templates-bake.sh):
  # nuclei's configuration names it and its release, its exclusion list is
  # in place, and a run with the sensor's flags against a closed port (no
  # network) logs no error, no template with a runtime error, and the
  # release. The bake gate checked the same at build; this checks the image
  # as shipped, as the runtime user.
  if release=$(docker run --rm --entrypoint cat "$image" /home/openctem/.config/nuclei/openctem-templates-release.json 2>&1); then
    tpl_version=$(printf '%s' "$release" | sed -nE 's/.*"version":"(v[0-9.]+)".*/\1/p')
    tpl_digest=$(printf '%s' "$release" | sed -nE 's/.*"digest":"(sha256:[a-f0-9]{64})".*/\1/p')
    if [ -n "$tpl_version" ] && [ -n "$tpl_digest" ]; then
      echo "  nuclei-templates: $tpl_version ($tpl_digest)"
    else
      fail "malformed nuclei-templates release record: $release"
    fi
  else
    fail "no nuclei-templates release record: $release"
    tpl_version=""
  fi
  if ! docker run --rm --entrypoint test "$image" -s /home/openctem/.config/nuclei/.nuclei-ignore; then
    fail "no .nuclei-ignore in nuclei's configuration directory"
  fi
  out=$(docker run --rm --network none --entrypoint nuclei "$image" \
    -u http://127.0.0.1:9 -jsonl -severity critical,high,medium,low -ni -disable-update-check \
    -disable-unsigned-templates -nc -timeout 2 -retries 0 2>&1 >/dev/null | sed "s/\x1b\[[0-9;]*m//g" || true)
  if printf '%s\n' "$out" | grep -qE '^\[(ERR|FTL)\]|templates with runtime error'; then
    fail "nuclei run with the baked templates reports errors:"
    printf '%s\n' "$out" | grep -E '^\[(ERR|FTL|WRN)\]' | head -n 10 | sed 's/^/    /' >&2
  elif [ -n "$tpl_version" ] && printf '%s\n' "$out" | grep -q "Current nuclei-templates version: ${tpl_version}"; then
    echo "  nuclei run: $(printf '%s\n' "$out" | grep -E 'Templates loaded for current scan' | sed 's/^\[INF\] //')"
  else
    fail "nuclei does not report the templates release ${tpl_version:-?}:"
    printf '%s\n' "$out" | tail -n 10 | sed 's/^/    /' >&2
  fi
  # The sensor adopts the baked set as its managed nuclei-templates content,
  # with the same release and digest (reported on heartbeats and results).
  status=$(docker run --rm --network none -e SENSOR_TOOLS=nuclei --entrypoint openctemio-sensor "$image" -content-status 2>&1 || true)
  if [ -n "$tpl_version" ] && printf '%s\n' "$status" | grep -q "\"version\": \"${tpl_version}\"" &&
    printf '%s\n' "$status" | grep -q "\"digest\": \"${tpl_digest}\""; then
    echo "  content: nuclei-templates ${tpl_version} adopted from the image"
  else
    fail "the sensor does not report the baked nuclei-templates ${tpl_version:-?} (${tpl_digest:-?}):"
    printf '%s\n' "$status" | tail -n 20 | sed 's/^/    /' >&2
  fi
fi

if [ "$variant" = default ]; then
  # Default CMD with no platform credentials: exit 2 and name the variables.
  set +e
  out=$(timeout 60 docker run --rm -e API_URL= -e API_KEY= "$image" 2>&1)
  rc=$?
  set -e
  if [ "$rc" -eq 2 ] && printf '%s\n' "$out" | grep -q 'API_URL' && printf '%s\n' "$out" | grep -q 'API_KEY'; then
    echo "  default CMD without credentials: exit 2, $(printf '%s\n' "$out" | head -n 1)"
  else
    fail "default CMD without credentials: exit $rc, want 2 with a message naming API_URL and API_KEY:"
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/    /' >&2
  fi
  cmd=$(docker image inspect --format '{{json .Config.Cmd}}' "$image")
  case "$cmd" in
    *'"-daemon"'*'"-enable-commands"'*) echo "  default CMD: $cmd" ;;
    *) fail "default CMD is $cmd, want the server-controlled daemon (-daemon -enable-commands)" ;;
  esac
fi

if [ "$failed" -ne 0 ]; then
  echo "== $image ($variant): FAILED" >&2
  exit 1
fi
echo "== $image ($variant): OK"
