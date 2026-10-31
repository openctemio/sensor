# OpenCTEM Sensor

The OpenCTEM sensor (`openctemio-sensor`) runs security tools inside your
network and reports the results to the [OpenCTEM](https://github.com/openctemio/openctem)
platform. It connects out to the platform over HTTPS, needs no inbound port,
and runs the scans the platform dispatches to it. Pick the image by profile
([docs/PROFILES.md](docs/PROFILES.md)): `-passive` (passive discovery only, no
program that touches a target), `-standard` (the default: nuclei and the recon
tools subfinder, dnsx, naabu, httpx, katana) or `-full` (every tool); opengrep,
semgrep, trivy and betterleaks also have their own images.

[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://go.dev/)

## Documentation

The guide lives at **[docs.openctem.io/sensors](https://docs.openctem.io/sensors/)**:

| I want to | Read |
|---|---|
| Pick between a sensor, CI and the feeds | [Which one do I need?](https://docs.openctem.io/sensors/#which-one-do-i-need) |
| Get a working sensor in five minutes | [Quickstart](https://docs.openctem.io/sensors/#quickstart-a-working-sensor-in-five-minutes) |
| Run a sensor, start to finish (prerequisites, pairing, volumes, upgrade, troubleshooting) | [Run the sensor](docs/RUN.md) and the [example Compose file](docker-compose.example.yml) |
| Run several sensors on one host (one per organization), each with its own credentials, volume and network | [deploy/multi](deploy/multi/README.md) |
| Install with Docker or Compose | [Deploy with Docker](https://docs.openctem.io/sensors/deploy-docker/) |
| Install on Kubernetes | [Deploy on Kubernetes](https://docs.openctem.io/sensors/deploy-kubernetes/) |
| Install the binary (systemd) | [Deploy as a binary](https://docs.openctem.io/sensors/deploy-binary/) |
| Pair it, grants and trust | [Pairing and enrollment](https://docs.openctem.io/sensors/pairing/) |
| Limit what it may scan | [Sensor-local policy](https://docs.openctem.io/sensors/network/#sensor-local-policy) |
| Keep scanner content current, content packs | [Scanner content and content packs](https://docs.openctem.io/sensors/content-delivery/) |
| Upgrade, roll back, back up, rotate its key, remove it | [Upgrade, back up and remove](https://docs.openctem.io/sensors/operate/) |
| Confinement, least privilege, TLS pinning | [Security notes](https://docs.openctem.io/sensors/security/) |
| Fix an error | [Troubleshooting](https://docs.openctem.io/sensors/troubleshooting/) |
| Every setting | [Settings reference](https://docs.openctem.io/sensors/settings/) |

The detailed reference that used to be this README (modes, the config file,
the outbox, scanner content, validation, signed
jobs, the scanner safety model, upgrade notes from the agent release) is in
[docs/REFERENCE.md](docs/REFERENCE.md). The local policy format is in
[docs/LOCAL_POLICY.md](docs/LOCAL_POLICY.md).

## Quick start

```bash
SENSOR_VERSION=v0.29.1   # the release to run; the seccomp profile comes from the same tag
curl -fsSLo openctem-sensor-seccomp.json \
  "https://raw.githubusercontent.com/openctemio/sensor/${SENSOR_VERSION}/docker/seccomp/sensor.json"

docker run -d --name openctem-sensor --restart unless-stopped \
  --stop-timeout 45 \
  --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp="$PWD/openctem-sensor-seccomp.json" \
  --dns-search . \
  -e XDG_CONFIG_HOME=/tmp/.config -e XDG_CACHE_HOME=/tmp/.cache \
  -e SENSOR_API_URL=https://openctem.example.com \
  -e SENSOR_PAIRING_CODE=XXXX-XXXX \
  -e SENSOR_ALLOWED_RANGES='203.0.113.0/24,*.example.com' \
  -v openctem-sensor-data:/var/lib/openctem \
  "ghcr.io/openctemio/sensor:${SENSOR_VERSION}"

docker logs -f openctem-sensor   # the fingerprint to compare (and the code, without SENSOR_PAIRING_CODE)
```

The console's install snippet (**Discovery > Sensors > Expect a sensor**)
fills in the platform URL, the code and the pins for you. Without
`SENSOR_PAIRING_CODE` the sensor prints a code for an administrator to enter
under **Pair a sensor** instead.

No mode or tool flags: the sensor runs as the daemon with platform commands
and enables every tool in the image whose binary passes its check. Narrow
the tools with the local policy's `tools.allow`. With
`SENSOR_PAIRING_CODE` (a code an administrator created with "expect a
sensor") the sensor attaches to that code on first start (the variable is
ignored once it is paired); `-e SENSOR_API_KEY=...`
still works instead of pairing. A sensor run by the instance administrator
for every organization (a shared sensor) is started with
`-e SENSOR_INSTANCE_ENROLLMENT_TOKEN=octe_...` instead: the single-use token
a super administrator issued under Console > System > Platform scanning (or
the install registered for its bundled sensor). The sensor pairs with its own
key and is enrolled without a further approval; the token is spent, never
printed, and ignored once the sensor is paired.

`--dns-search .` makes the tools look names up exactly as written, without
the host's search domain appended. Set `-e SENSOR_SANDBOX_NETWORK=required`
to refuse to start rather than run the tools unconfined (the default, `auto`,
falls back with a warning).

Approve the code under **Discovery > Sensors > Pair a sensor** after
comparing the fingerprint, then check that the log says
`Tool network: confined` and `Preflight: ... 0 failed`. Keep the
`openctem-sensor-data` volume: it holds the sensor's private key. The full
walk-through, including a private platform CA, is the
[quickstart](https://docs.openctem.io/sensors/#quickstart-a-working-sensor-in-five-minutes).

## Troubleshooting pairing

A current sensor keeps retrying pairing in the process, with a message each
time and a growing delay (up to 5 minutes): fix the cause and watch
`docker logs -f openctem-sensor`, there is no need to restart it. An older
sensor exits and Docker restarts it, which spends the pairing budget of your
address faster; upgrade it.

| The log says | Cause and fix |
|---|---|
| `this machine's clock is 4h10m0s ahead of the platform's clock` (sensors before the clock-skew message: `HTTP 401` ... `Invalid credentials` on start) | Request signatures allow 2 minutes of clock difference. Check both the sensor host and the platform host: `timedatectl` should say `System clock synchronized: yes`; `chronyc tracking` shows the offset. Step a wrong clock with `sudo chronyc makestep`, and let chrony step large offsets at any time with `makestep 1 -1` in `/etc/chrony/conf.d/`. |
| `Rate limited by the platform (HTTP 429); retrying in N s` | The platform limits pairing starts per network address (every sensor and probe behind one office address shares it). Starts with a `SENSOR_PAIRING_CODE` have their own budget per code. Wait, and avoid restart loops and repeated manual probes. |
| `refused the instance enrollment token` | The token is single use and spent, expired or unknown: ask a super administrator for a new one. |
| A code is printed and nothing happens | An administrator must enter the code under **Discovery > Sensors > Pair a sensor** and approve it after comparing the fingerprint. To pair without typing a code, create one under **Expect a sensor** and start the sensor with `-e SENSOR_PAIRING_CODE=XXXX-XXXX`. |
| `The pairing request expired; starting a new one.` | Nobody approved the request within 10 minutes; the sensor starts a new one (a new code without `SENSOR_PAIRING_CODE`). |

## Install

| Artifact | Where |
|---|---|
| Images | `ghcr.io/openctemio/sensor:<version>` (default: nuclei and the recon tools) and `:<version>-opengrep`, `-semgrep`, `-trivy`, `-betterleaks`, `-nuclei`; mirrored to Docker Hub as `openctemio/sensor` |
| Binaries | `openctemio-sensor_<version>_<os>_<arch>.tar.gz` on each [release](https://github.com/openctemio/sensor/releases) (Linux, macOS, Windows); install the scanners yourself (`openctemio-sensor -check-tools`) |
| Seccomp profile | [`docker/seccomp/sensor.json`](docker/seccomp/sensor.json), per release |

Images and the release checksums are signed keyless with cosign; verify with
cosign v3 as shown in [Deploy with Docker](https://docs.openctem.io/sensors/deploy-docker/#1-pick-an-image)
and [Deploy as a binary](https://docs.openctem.io/sensors/deploy-binary/#download-a-release).

## Command line

```bash
openctemio-sensor -help                     # every flag
openctemio-sensor -version
openctemio-sensor -list-tools               # scanners and whether each is installed
openctemio-sensor pair [CODE] | pair -repair  # pair, or replace the key
openctemio-sensor policy validate|digest|explain|install   # the local policy
openctemio-sensor -outbox-status | -outbox-requeue-dead | -content-status
openctemio-sensor -standalone -tool nuclei -target https://app.example.com   # one scan, no platform
```

The daemon is the default mode; a run is one-shot when `-tool`, `-target`,
`-push`, `-json` or `-output` is given, with `-daemon=false`, or in a CI job
(`CI=true`).

**Upgrading:** `-daemon`, `-enable-commands` and `SENSOR_TOOLS` / `-tools`
still work for one release, with a deprecation warning: the first two are
the defaults now, and in the daemon `SENSOR_TOOLS` / `-tools` only narrows the
detected tools (a listed tool that is not installed is ignored and named in
the log). `-enable-recon`, `-enable-vulnscan` and the other platform-mode
flags are ignored with a warning. To opt out of platform commands, use
`-enable-commands=false`, `sensor.enable_commands: false` or `-standalone`.

## Building

```bash
make build        # bin/openctemio-sensor
make build-all    # every release platform
make test
```

The sensor is built on [openctemio/sdk-go](https://github.com/openctemio/sdk-go).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes add a file under
[`changelog.d/`](changelog.d/README.md); the release folds them into
[CHANGELOG.md](CHANGELOG.md).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Related projects

- [openctemio/openctem](https://github.com/openctemio/openctem): the platform (API and web console)
- [openctemio/sdk-go](https://github.com/openctemio/sdk-go): the Go SDK the sensor is built on
- [openctemio/ci](https://github.com/openctemio/ci): CI scanning
- [openctemio/helm-charts](https://github.com/openctemio/helm-charts): the Helm chart, with an optional bundled sensor
- [docs.openctem.io](https://docs.openctem.io): the documentation

## License

GNU General Public License v3.0; see [LICENSE](LICENSE).
