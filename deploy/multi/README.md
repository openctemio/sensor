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
SENSOR_VERSION=v0.32.0
mkdir -p ~/openctem-sensors && cd ~/openctem-sensors
for f in compose.yaml sensors.sh .env.example .gitignore; do
  curl -fsSLO "https://raw.githubusercontent.com/openctemio/sensor/${SENSOR_VERSION}/deploy/multi/$f"
done
chmod +x sensors.sh && cp .env.example .env
```

`.env` holds `SENSOR_VERSION`, the release every sensor runs, and the default
limits. Then, per sensor (create the pairing code in that organization's
console under **Discovery > Sensors > Expect a sensor**):

```bash
./sensors.sh add acme --api-url https://openctem.example.com --pairing-code XXXX-XXXX
$EDITOR sensors/acme/policy/sensor-policy.yaml   # what acme may scan; [] allows nothing
./sensors.sh pair acme                           # start it, show the fingerprint, wait for approval
```

`pair` starts only that sensor and shows the lines that matter while it
waits: the code (when the sensor shows one), the fingerprint and the key.
Approve the sensor in the console only when the console shows the same
fingerprint and the organization you mean. Once it is paired, `pair` clears
the spent `SENSOR_PAIRING_CODE` from its `sensor.env` and exits; it gives up
after 15 minutes (`PAIR_WAIT_SECONDS`), and Ctrl-C stops the waiting, not the
sensor: the message says to approve in the console and run `pair` again to
watch. A sensor paired earlier is reported at once. Before it starts the
sensor, `pair` pulls its image when it is not on the host yet, with progress;
a pull that takes longer than 10 minutes (`PULL_TIMEOUT_SECONDS`) stops with a
hint (a pull interrupted with Ctrl-C can leave a stale download that makes the
next one hang until the container runtime restarts).

To pair again with a new code (the old one expired, or the sensor was
stopped before anyone approved it), make the code in the console and run
`./sensors.sh pair acme --pairing-code XXXX-XXXX`: it writes the code into
`sensors/acme/sensor.env` and recreates the container. The sensor keeps its
key; the platform closes the key's earlier request that nobody approved and
opens the new one. A key that was approved once never pairs again: the
sensor then says its key is already registered, and needs its identity back
or a new key.

Without `--pairing-code` the sensor shows a code for an administrator of that
organization to enter under **Pair a sensor**. Creating the code in the
console first (**Expect a sensor**) and passing it with `--pairing-code` is
the safer order: the code then comes from the person who approves, so nobody
has to send a code around. `./sensors.sh up` starts every sensor at once.

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
`mem_limit: 8g`, `cpus: 4`, a private platform CA (mount the PEM into
`sensors/<name>/policy/` and set `SENSOR_CA_CERT_FILE` in its `sensor.env`), or
any setting of the [settings reference](https://docs.openctem.io/sensors/settings/)
in its `sensor.env`.

## Operate

| Task | Command |
|---|---|
| Pair one sensor (or check that it is paired) | `./sensors.sh pair acme` |
| Pair again with a new code | `./sensors.sh pair acme --pairing-code XXXX-XXXX` (writes the code, recreates the container) |
| State of every sensor | `./sensors.sh status` (containers, and each one's last pairing or preflight line) |
| Follow one log | `./sensors.sh logs acme` |
| Upgrade every sensor | `./sensors.sh upgrade vX.Y.Z`: verifies the image signature (cosign, keyless; a cosign container when cosign is not installed), pulls, fetches the release's seccomp profile, sets `SENSOR_VERSION` in `.env`, recreates the containers. Identity, outbox and content cache stay on the volumes; no sensor pairs again. |
| Stop one sensor's jobs | `touch sensors/acme/policy/STOP` (remove the file to resume) |
| Restart one | `docker compose restart acme` (after a policy change) |
| Re-pair one (new key, same sensor) | `./sensors.sh repair acme --pairing-code XXXX-XXXX` ([Re-pair a sensor](#re-pair-a-sensor)) |
| Remove one | `./sensors.sh remove acme [--purge]` ([Remove a sensor](#remove-a-sensor)) |

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
