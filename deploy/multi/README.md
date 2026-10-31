# Several sensors on one host

This directory runs any number of OpenCTEM sensors on one Docker host, from
one directory, with nothing shared between them that matters: each sensor has
its own credentials, data, network and policy. Use it when one host scans for
several organizations or platforms (one sensor each), instead of one folder
and one Compose file per sensor.

| Per sensor | What | Why |
|---|---|---|
| `sensors/<name>/sensor.env` (mode 0600) | Platform URL, `SENSOR_NAME`, pairing code | Each sensor pairs with its own platform or organization. Compose passes the file to that service only. |
| Volume `<name>-data` at `/var/lib/openctem` | Identity (private key), encrypted outbox and store, content cache | A sensor's only credential. Never shared or copied: a second process on one outbox refuses to start, and a cloned identity is flagged `identity_cloned`. |
| Network `<name>` | Its own bridge, inter-container traffic off | No sensor can reach another sensor's container. |
| `sensors/<name>/policy/` (read-only) | `sensor-policy.yaml` and the kill switch `STOP` | Each network owner limits their sensor; `touch sensors/<name>/policy/STOP` stops only that one. |

Shared, from `compose.yaml` (`x-sensor`): the image and release (`.env`), and
the hardening: read-only root filesystem, every capability dropped,
`no-new-privileges`, the release's seccomp profile (per-task network
confinement, `SENSOR_SANDBOX_NETWORK=required`), a size-capped `/tmp`, memory,
CPU and process limits, log rotation. The seccomp profile file is the only
file the sensors share (read-only and public). The Docker socket is never
mounted.

## Which setup

| Setup | Use when |
|---|---|
| One sensor ([docker-compose.example.yml](../../docker-compose.example.yml), [docs/RUN.md](../../docs/RUN.md)) | One organization, one sensor on the host. |
| **This directory** | One host runs sensors for several organizations, tenants or platforms, each paired and administered separately. Each sensor's owner sees only their sensor. |
| A shared sensor ([Shared sensors](https://docs.openctem.io/sensors/shared-sensors/)) | The instance administrator runs one sensor that takes jobs of every organization (shared mode isolates each job). Nothing to set up per organization. |
| Separate hosts | The organizations must not share a kernel, a host administrator or a network vantage point, or one host cannot carry the load ([Size the host](../../docs/RUN.md#size-the-host-and-keep-it-to-itself)). |

The sensors on one host share its kernel, CPU, disk and outbound address, and
anyone with Docker access on the host can read every sensor's volume: put the
host under one administrator every organization trusts.

## Set up

Copy this directory to the host (outside a git checkout, since `sensors.sh`
edits `compose.yaml`):

```bash
SENSOR_VERSION=v0.33.0
mkdir -p ~/openctem-sensors && cd ~/openctem-sensors
for f in compose.yaml sensors.sh .env.example .gitignore; do
  curl -fsSLO "https://raw.githubusercontent.com/openctemio/sensor/${SENSOR_VERSION}/deploy/multi/$f"
done
chmod +x sensors.sh && cp .env.example .env
```

`.env` holds `SENSOR_VERSION`, the release every sensor runs, and the default
limits. Then one command per sensor:

```bash
./sensors.sh add acme --api-url https://openctem.example.com
```

`add` writes the sensor's settings, starts only that sensor and shows what it
prints while it waits:

```
  Pair this sensor: open https://openctem.example.com/activate?code=K7QM-4ZTD
  Code:        K7QM-4ZTD
  Fingerprint: 821 · melon · basil · bagel
```

Open the link while signed in to the console (an administrator of the
organization the sensor is for), check the organization, pick the fingerprint
this terminal shows and approve. `add` ends by itself once the sensor is
paired, and clears a spent `SENSOR_PAIRING_CODE` from its `sensor.env`. It
gives up after 15 minutes (`PAIR_WAIT_SECONDS`); Ctrl-C stops the waiting,
not the sensor (`./sensors.sh pair acme` watches again). Before it starts the
sensor it pulls the image with progress; a pull longer than 10 minutes
(`PULL_TIMEOUT_SECONDS`) stops with a hint (a pull interrupted with Ctrl-C can
leave a stale download that makes the next one hang until the container
runtime restarts). Nothing needs editing: the sensor follows the
organization's scope ([The local policy is optional](#the-local-policy-is-optional)).

- A platform with a private certificate authority: add `--ca-sha256 HEX`
  (the SHA-256 of the platform's ROOT CA, from the console's install command;
  the sensor fetches the CA itself) or `--ca-file platform-ca.pem` (the
  command prints the subject and SHA-256 of every certificate in the file).
  Without either the sensor stops with one sentence naming the authority it
  was shown, instead of retrying. For a sensor that exists already:
  `./sensors.sh set-ca acme --sha256 HEX` or `--file platform-ca.pem` (see
  [Private certificate authority](#private-certificate-authority)).
- Automation can start from a code made in the console (or with the API):
  `--pairing-code XXXX-XXXX`. The sensor then shows that same code and link.
- `--no-start` only writes the sensor; `./sensors.sh pair acme` starts and
  pairs it later. `./sensors.sh up` starts every sensor at once.

A sensor that was stopped before anyone approved it keeps its key: start it
again (`./sensors.sh pair acme`) and open its new link. A key that was
approved once never pairs again: the sensor then says its key is already
registered, and needs its identity back or a re-pair.

### The local policy is optional

A sensor scans only what its organization's scope allows. The owner of the
host may narrow one sensor further: write
`sensors/acme/policy/sensor-policy.yaml` (it can only narrow; the platform
never writes it), uncomment `SENSOR_LOCAL_POLICY` in `sensors/acme/sensor.env`,
then `./sensors.sh stop acme && ./sensors.sh start acme`. `touch
sensors/acme/policy/STOP` stops every job of that sensor while the file
exists.

A directory set up with an older kit has `SENSOR_LOCAL_POLICY` in the
`x-sensor` block of `compose.yaml`, so every sensor there needs a policy file
(`add` then writes one that narrows nothing). To let those sensors follow the
organization's scope: move the line into the `sensor.env` of each sensor that
should keep its file, then delete it from `x-sensor` and run `./sensors.sh up`.

`sensors.sh add` refuses a name that exists, writes the env file owner-only,
appends the service, volume and network blocks to `compose.yaml`, and puts
the file back as it was when the result does not validate
(`docker compose config`). A block looks like this; edit it freely:

```yaml
  acme:
    <<: *sensor
    env_file: [sensors/acme/sensor.env]
    volumes:
      - acme-data:/var/lib/openctem
      - ./sensors/acme/policy:/etc/openctem/policy:ro
    networks: [acme]
```

Per-sensor additions go in its block: `cap_add: [NET_RAW]` (naabu SYN scans),
`mem_limit: 8g`, `cpus: 4`, or
any setting of the [settings reference](https://docs.openctem.io/sensors/settings/)
in its `sensor.env`.

## Operate

| Task | Command |
|---|---|
| Add, start and pair one sensor | `./sensors.sh add acme --api-url URL [--ca-sha256 HEX \| --ca-file FILE]` |
| Trust a private CA on an existing sensor | `./sensors.sh set-ca acme --sha256 HEX` or `--file FILE` (writes `sensor.env`, recreates the container) |
| Update the kit's own files | `./sensors.sh self-update vX.Y.Z` ([Update the kit](#update-the-kit)) |
| Pair one sensor (or check that it is paired) | `./sensors.sh pair acme` |
| Pair with a code made in the console | `./sensors.sh pair acme --pairing-code XXXX-XXXX` (writes the code, recreates the container) |
| State of every sensor | `./sensors.sh status`: one line each, "running and paired", "waiting for approval: open <link>", or why not |
| Stop or start one | `./sensors.sh stop acme`, `./sensors.sh start acme` (key and queued results stay) |
| Stop everything | `./sensors.sh down` (removes the containers, never the volumes) |
| Follow one log | `./sensors.sh logs acme` |
| Upgrade every sensor | `./sensors.sh upgrade [--self-update] vX.Y.Z`: verifies the image signature (cosign, keyless; a cosign container when cosign is not installed), pulls, fetches the release's seccomp profile, sets `SENSOR_VERSION` in `.env`, recreates the containers. Identity, outbox and content cache stay on the volumes; no sensor pairs again. |
| Stop one sensor's jobs | `touch sensors/acme/policy/STOP` (remove the file to resume) |
| Re-pair one (new key, same sensor) | `./sensors.sh repair acme --pairing-code XXXX-XXXX` ([Re-pair a sensor](#re-pair-a-sensor)) |
| Remove one | `./sensors.sh remove acme [--purge]` ([Remove a sensor](#remove-a-sensor)) |

### Private certificate authority

When the platform's certificate comes from a private CA, `./sensors.sh status`
says so ("its certificate authority is not trusted"). Pin the platform's
**root** CA by its SHA-256 (from the console's install command, which you copy
from your signed-in console; the sensor's own message lists every certificate
the platform presented, intermediates included, so compare the root's hash
with the console's before using it):

```sh
./sensors.sh set-ca acme --sha256 <root-ca-sha256>      # hex, colons optional, a,b for a rotation
./sensors.sh set-ca acme --file platform-ca.pem         # air-gapped: the CA itself
./sensors.sh status
```

`--sha256` sets `SENSOR_CA_SHA256` in `sensors/acme/sensor.env`; the sensor
then fetches the CA from the platform and accepts it only if a certificate in
it has that hash and signs the platform's chain. `--file` installs the file as
`sensors/acme/policy/platform-ca.pem` and sets `SENSOR_CA_CERT_FILE`. Both keep
`sensor.env` at mode 0600 and recreate the container. Nothing is trusted without
one of the two.

### Local policy: allow everything the platform signs

A sensor follows the platform's scope by default. To make the sensor's own
local policy explicit and wide, so that it refuses nothing the platform signs:

```sh
./sensors.sh set-policy acme --allow-all        # writes sensors/acme/policy/sensor-policy.yaml, recreates acme
./sensors.sh set-policy acme --platform-scope   # stop reading the file again (the file stays)
```

`--allow-all` writes a v2 policy with `targets.allow: ["*"]` and sets
`SENSOR_LOCAL_POLICY` in `sensor.env`. The built-in deny list and the
private-range rules still apply. An existing policy file is kept as
`sensor-policy.yaml.bak-<UTC time>`. The `"*"` form needs sensor v0.34.0 or
newer (the version the sensor's image runs, read from its compose block); on an
older one the command writes a v1 file with `0.0.0.0/0` and `::/0` and says so.
That covers IP addresses only: a job whose target is a domain name is refused
until you upgrade and run the command again.

### Update the kit

`./sensors.sh upgrade` moves the image only. The kit's own files
(`sensors.sh`, `compose.yaml`, `README.md`, `.env.example`) change between
releases: for example a `compose.yaml` from an older kit hard-wires a local
policy file, so deleting that file stops the sensor from starting and the
sensor never simply follows the platform's scope. Update them with:

```sh
./sensors.sh self-update vX.Y.Z      # or: ./sensors.sh upgrade --self-update vX.Y.Z
./sensors.sh up                      # recreate the sensors with the new compose.yaml
```

What it does: downloads the release's kit files and a keyless cosign-signed
`deploy-multi.SHA256SUMS` (certificate identity: the sensor repository's
`release.yml` workflow at that tag, issuer GitHub Actions), verifies the
signature and every checksum before changing anything, backs the current files
up as `<file>.bak-<UTC time>`, writes the new template and re-inserts your
existing services, volumes and networks sections unchanged (per-sensor edits
stay), checks `docker compose config -q` (restoring the backups if it fails)
and prints how many lines changed per file. It never touches `sensors/`,
volumes or containers. A sensor whose `policy/sensor-policy.yaml` narrows scope
keeps it only if its `sensor.env` has `SENSOR_LOCAL_POLICY=...`; the command
names such sensors. `upgrade` offers the update when `compose.yaml` is from an
older kit (a question on a terminal, a hint otherwise) and never runs it
without `--self-update` or a yes. Releases before this feature have no signed
kit files; update those by hand.

### Re-pair a sensor

Use it for a sensor whose key was lost, corrupted or revoked, or that moved
to another host (the console shows it as needing a new key). In the console
open **Sensors > the sensor > Re-pair...** and copy the code it gives (it
re-pairs that sensor only; the sensor keeps its name, zones and grant), then:

```bash
./sensors.sh repair acme --pairing-code XXXX-XXXX
```

It says "This replaces the key of acme. Its current key keeps working until
you approve the re-pair in the console, unless you revoked it there." and asks
for confirmation (`--yes` skips the question). Then it stops the sensor,
deletes **only** the identity directory (`state/identity`) of `acme-data` with
a throwaway container (no network, read-only, no capabilities, no Docker
socket; `REPAIR_HELPER_IMAGE` replaces its image), writes the code into
`sensors/acme/sensor.env` and runs the same pairing as `pair`: it shows the
fingerprint, waits for you to approve the re-pair in the console, and clears
the spent code. The outbox and the content caches stay: a re-pair keeps the
sensor's id, so results queued under the old key are delivered under the new
one. The code is `XXXX-XXXX` (letters and digits without I, L, O and U, any
case, the dash optional).

### Remove a sensor

```bash
./sensors.sh remove acme            # stop and remove the container, config and compose.yaml blocks
./sensors.sh remove acme --purge    # also delete the acme-data volume
```

`remove` asks for confirmation (`--yes` skips it), runs `docker compose rm
-sf acme` for that service only, deletes `sensors/acme/` and takes the
sensor's service, volume and network blocks out of `compose.yaml` (it puts the
file back when the rest does not validate). Without `--purge` the volume stays,
so adding `acme` again finds its key. With `--purge` the volume is deleted:
the key **and the results in its outbox that the platform has not accepted yet
are lost**, and the sensor must be re-paired or added again. Also revoke or
delete the sensor in the console (**Sensors > the sensor > Revoke access** or
**Delete**): removing it here does not stop its key from working there.

### Pin one sensor to another release

Give its block its own image and the profile of that release, then fetch the
profile (`docker run --rm --network none ghcr.io/openctemio/sensor:vX.Y.Z
seccomp-profile > seccomp/sensor-vX.Y.Z.json`):

```yaml
  acme:
    <<: *sensor
    image: ghcr.io/openctemio/sensor:vX.Y.Z
    security_opt: [no-new-privileges:true, seccomp=./seccomp/sensor-vX.Y.Z.json]
```

### Back up

Back up each `<name>-data` volume (leave out the `content/` cache and
`workspaces/`), encrypted, as described in
[What lives in /var/lib/openctem](../../docs/RUN.md#what-lives-in-varlibopenctem).
Never restore one sensor's backup into another sensor's volume.
