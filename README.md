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
SENSOR_VERSION=v0.33.0   # the release to run; the seccomp profile comes from the same tag
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
  -v openctem-sensor-data:/var/lib/openctem \
  "ghcr.io/openctemio/sensor:${SENSOR_VERSION}"

docker logs -f openctem-sensor   # the link to approve it on, its code and its fingerprint
```

The sensor prints `Pair this sensor: open https://<platform>/activate?code=XXXX-XXXX`
with its code and fingerprint: open the link signed in to the console, pick
the fingerprint the sensor printed and approve. The console's **Sensors >
Add sensor** command does all of this in one paste (the platform URL, a
single-use code so the console finds the sensor by itself, the pins, a
private CA, and a watch that ends once the sensor is paired). No local
policy is needed: the sensor follows the organization's scope; the host
owner may narrow it ([docs/LOCAL_POLICY.md](docs/LOCAL_POLICY.md), or
`-e SENSOR_ALLOWED_RANGES='203.0.113.0/24,*.example.com'`).

No mode or tool flags: the sensor runs as the daemon with platform commands
and enables every tool in the image whose binary passes its check. Narrow
the tools with the local policy's `tools.allow`. With
`SENSOR_PAIRING_CODE` (a code from the console's command, or made with the
API for automation) the sensor pairs under that code on first start (the variable is
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

Approve it from its link (or enter its code on the console's `/activate`
page) after picking its fingerprint, then check that the log says
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
| `Pair this sensor: open ...` and nothing happens | An administrator of the organization opens that link (or enters the code on the console's `/activate` page), picks the fingerprint the sensor printed and approves. |
| `the platform's TLS certificate is signed by an authority this host does not trust` | The platform uses a private CA (or something intercepts TLS). Compare the SHA-256 the sensor printed with the one the console shows under its install command, then use that command (it sets `SENSOR_CA_SHA256`), or set it yourself, or give the CA file with `SENSOR_CA_CERT_FILE`. See [Private certificate authority](#private-certificate-authority). |
| `the request was refused` | An administrator rejected it, or picked a fingerprint this host did not show. The sensor starts a new request: open its new link. |
| `The pairing request expired; starting a new one.` | Nobody approved the request within 10 minutes; the sensor starts a new one (a new code without `SENSOR_PAIRING_CODE`). |

## Private certificate authority

If the platform's TLS certificate comes from your own certificate authority
(CA), the sensor does not trust it and stops with a message that lists every
certificate the platform presented, with each SHA-256. Without a pin or a CA
file nothing is trusted automatically: the sensor never accepts a certificate
because it was offered.

Two ways to trust it. Use the first unless the host has no route to the
platform at pairing time.

**Pin the root (recommended).** Set `SENSOR_CA_SHA256` to the SHA-256 of the
platform's **root** CA certificate (hex, colons optional, several separated by
commas for a root rotation). When the chain is untrusted, the sensor fetches
the CA bundle from `<SENSOR_API_URL>/api/v1/sensors/platform-ca`, accepts it
only if one certificate in it has a pinned hash and that certificate signs the
platform's chain, and stores it in its state directory. The hash is the root's,
not the server's or an intermediate's: the message the sensor prints marks each
presented certificate, so pick the root (the one that signs itself).

**Give it the CA file** (air-gapped hosts): set `SENSOR_CA_CERT_FILE` to a PEM
file with the CA (see the examples).

Where the pin comes from: the console's install command carries it. You copy
that command from your signed-in console, the same trust path as the pairing
code, so an attacker who sits between the sensor and the platform cannot
choose the pin. Do not take the hash from the sensor's own message without
comparing it with the console (the message shows what was presented, which on
a hostile network is the attacker's certificate).

```sh
# docker run: add one -e
docker run -d --name openctem-sensor ... \
  -e SENSOR_API_URL=https://openctem.example.com \
  -e SENSOR_CA_SHA256=<root-ca-sha256> \
  ghcr.io/openctemio/sensor:<version>

# or the file: mount it read-only
#   -v ./platform-ca.pem:/certs/platform-ca.pem:ro -e SENSOR_CA_CERT_FILE=/certs/platform-ca.pem
```

```yaml
# docker compose (docker-compose.example.yml): under environment:
      SENSOR_CA_SHA256: <root-ca-sha256>
```

```sh
# deploy/multi (several sensors on one host): a new sensor
./sensors.sh add acme --api-url https://openctem.example.com --ca-sha256 <root-ca-sha256>
# an existing sensor (writes sensor.env, recreates the container)
./sensors.sh set-ca acme --sha256 <root-ca-sha256>
./sensors.sh set-ca acme --file platform-ca.pem     # or the CA file
./sensors.sh status
```

```yaml
# Kubernetes / Helm: the sensor container's env list (the platform chart's
# openctem-ca is separate; this is the sensor's own deployment)
env:
  - name: SENSOR_CA_SHA256
    value: "<root-ca-sha256>"
```

Check it worked: the log shows the pairing line (`Pair this sensor: open ...`)
instead of "does not trust". Rotating the platform's root: set both hashes
(`old,new`) until every sensor has refreshed, then drop the old one.
`SENSOR_CA_FINGERPRINT` (pins the platform's sensor CA after pairing) is a
different setting and does not make a private CA trusted.

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
