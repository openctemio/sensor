# Run the sensor

This is the complete guide to running the OpenCTEM sensor in Docker. The same
guide is on the docs site, under [Sensors](https://docs.openctem.io/sensors/run-the-sensor/).

1. [Prerequisites](#prerequisites)
2. [Get a pairing code](#get-a-pairing-code)
3. [Start the sensor](#start-the-sensor)
4. [What lives in /var/lib/openctem](#what-lives-in-varlibopenctem)
5. [Environment variables](#environment-variables)
6. [Capabilities and seccomp](#capabilities-and-seccomp)
7. [Upgrade](#upgrade)
8. [Several sensors on one host](#several-sensors-on-one-host)
9. [Kubernetes](#kubernetes)
10. [Uninstall and re-pair](#uninstall-and-re-pair)
11. [Troubleshooting](#troubleshooting)

## Prerequisites

| Need | Detail |
|---|---|
| Docker | Docker Engine 24 or later on Linux (amd64 or arm64). Docker Compose v2.20 or later for the Compose file (`docker compose version`). Linux 5.13 or later lets the tool sandbox use Landlock; older kernels work with a warning. |
| Size | 2 CPUs and 2 GiB of RAM for a small sensor; 4 CPUs and 4 GiB if several scans run at once. Disk: 10 GiB free for the data volume (scanner content is about 1 GiB, the workspace budget 4 GiB, the outbox up to 1 GiB by default). The sensor stops claiming work when the volume is nearly full, see [Troubleshooting](#low-disk-the-sensor-stops-claiming-work). |
| Network | Outbound HTTPS (443, or the port of your platform URL) to the platform API. A platform with sensor mTLS also needs outbound TCP to its mTLS port (9443 by default; the platform's install snippet shows it). No inbound port. The host also needs to reach the targets it scans. |
| Proxy | Optional. If the host reaches the platform through an HTTP proxy, set `HTTPS_PROXY` (and `NO_PROXY`). A TLS-inspecting proxy needs `SENSOR_TRANSPORT=https`. |
| Clock | Synchronised (chrony or systemd-timesyncd). Signatures allow 2 minutes of difference. |
| Platform | The platform URL and someone with the **Pair sensors** and **Approve sensors** permissions. |

## Get a pairing code

In the console open **Discovery > Sensors > Expect a sensor**, name the
sensor and choose **Create a pairing code**. You get a code like `K7QM-4ZTD`
and an install snippet that already holds your platform URL. Keep the code
private until the sensor has used it; it is spent on first use.

Without a code the sensor prints one at start, and an administrator enters it
under **Pair a sensor**. Either way, compare the fingerprint the sensor prints
with the one the console shows before approving.

## Start the sensor

Use a **named volume** for `/var/lib/openctem`. Docker creates it with the
sensor's owner, so there is nothing to `chown`.

```bash
SENSOR_VERSION=v0.30.0   # the release to run
docker run --rm "ghcr.io/openctemio/sensor:${SENSOR_VERSION}" seccomp-profile > openctem-sensor-seccomp.json

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

docker logs -f openctem-sensor
```

With Compose, use [`docker-compose.example.yml`](../docker-compose.example.yml)
(it matches this guide): put `SENSOR_API_URL` and `SENSOR_PAIRING_CODE` in a
`.env` file next to it, then `docker compose up -d`.

The log should end with `Tool network: confined` and `Preflight: ... 0
failed`, and the console shows the sensor online. After the first start the
pairing code is ignored.

### A bind mount instead of a named volume

A host directory mounted at `/var/lib/openctem` keeps the image's ownership
out: the sensor runs as a non-root user and cannot write a directory another
user owns. Give it the directory first:

```bash
sudo mkdir -p /srv/openctem-sensor
sudo chown -R 999:999 /srv/openctem-sensor
docker run ... -v /srv/openctem-sensor:/var/lib/openctem ...
```

| Image | User (uid:gid) |
|---|---|
| default (`ghcr.io/openctemio/sensor:<version>`), and the profiles `-passive`, `-standard`, `-full` ([PROFILES.md](PROFILES.md)) | `999:999` |
| the per-tool images (`-opengrep`, `-semgrep`, `-trivy`, `-betterleaks`, `-nuclei`) | `1001:1001` |
| the slim image (no tools) | `65532:65532` (distroless `nonroot`) |

The ids differ per image because each image has always run as that user and a
volume written by one release must stay readable by the next; they are not
changed. Use the uid of the image you run. With SELinux add `:Z` to the mount
(`-v /srv/openctem-sensor:/var/lib/openctem:Z`). With rootless Docker or user
namespaces the host owner is the mapped id, not 999: use a named volume.

The sensor checks its data directories before it does anything else. If it
cannot write them it exits with code 1 and prints the path, the owner, its own
uid:gid and the two fixes.

## What lives in /var/lib/openctem

Mount **one** volume at `/var/lib/openctem`. The image declares no `VOLUME`
on purpose: an anonymous volume looks persistent and is lost with the
container.

| Directory | Holds | Keep it? |
|---|---|---|
| `state/` | The sensor's identity: its private key, client certificate and pinned CAs, and the renewed API key | **Yes.** It is the sensor's only credential. Back it up encrypted, never share it, never run two sensors from one copy. Without it the sensor must be paired again. |
| `store/` | The encrypted local store: keys of the sealed outbox items, the job journal, `master.key` | **Yes**, with the outbox. `SENSOR_STORE_KEY_FILE` can point at a mounted secret to keep the key off the volume. |
| `outbox/` | Results not yet accepted by the platform (encrypted) | **Yes.** Without it, results queued during an outage or an upgrade are lost. One sensor per outbox. |
| `workspaces/` | Per-job scratch directories, removed when a job ends | No. Swept at start. |
| `content/` | Scanner content (nuclei templates; trivy database and semgrep rules on the per-tool images) | No. A cache, downloaded again when missing. |

Back up (the `content/` cache can be left out):

```bash
docker run --rm -v openctem-sensor-data:/data:ro -v "$PWD":/backup alpine \
  tar -C /data --exclude=./content --exclude=./workspaces -czf /backup/openctem-sensor-data.tgz .
```

Restore with the old sensor stopped, into a new volume (`tar -xzpf` keeps
owners and modes). See [Upgrade, back up and remove](https://docs.openctem.io/sensors/operate/).

## Environment variables

The common ones. Every setting is in the
[settings reference](https://docs.openctem.io/sensors/settings/).

| Group | Variable | Default | Meaning |
|---|---|---|---|
| Platform | `SENSOR_API_URL` | none (required) | The platform URL. Must reach the API directly; redirects are refused. |
| Pairing | `SENSOR_PAIRING_CODE` | none | A code from **Expect a sensor** (`XXXX-XXXX`). Used while the sensor has no identity; ignored once paired. |
| Pairing | `SENSOR_API_KEY` | none | A legacy bearer key instead of pairing. |
| Pairing | `SENSOR_INSTANCE_ENROLLMENT_TOKEN` | none | A single-use token for a sensor shared by every organization. |
| Identity | `SENSOR_NAME` | `sensor-<hostname>` | The name the sensor proposes; the approver may change it. |
| TLS | `SENSOR_CA_CERT_FILE` | none | A PEM file with the platform's private CA. |
| TLS | `SENSOR_CA_FINGERPRINT` | none | SHA-256 fingerprint of the platform CA (from the install snippet) to pin. |
| Network | `HTTPS_PROXY`, `NO_PROXY` | none | A proxy to the platform. |
| Network | `SENSOR_CONTROL_PROXY` | none | A proxy for the control channel only. |
| Network | `SENSOR_TRANSPORT` | `auto` | Leave it. `https` behind a TLS-inspecting proxy. |
| Scope | `SENSOR_ALLOWED_RANGES` | none | What the sensor may scan (CIDRs, IPs, names, `*.domain`). Without it or a policy file a new sensor refuses network jobs. |
| Scope | `SENSOR_ALLOW_PRIVATE_TARGETS` | off | `1` allows RFC 1918 and IPv6 ULA targets. |
| Content | `SENSOR_CONTENT` | on | `off` turns managed scanner content off. |
| Content | `SENSOR_CONTENT_DIR` | `/var/lib/openctem/content` | Where content is kept. |
| Content | `SENSOR_CONTENT_REFRESH_INTERVAL`, `SENSOR_CONTENT_KEEP` | see settings | How often content refreshes and how many versions stay. |
| Data | `SENSOR_STATE_DIR`, `SENSOR_OUTBOX_DIR`, `SENSOR_STORE_DIR`, `SENSOR_WORKSPACE_DIR` | under `/var/lib/openctem` | Move a directory elsewhere. Each is checked at start. |
| Limits | `SENSOR_MAX_JOBS` | from CPU, memory and tool cost | Cap on jobs at once, 1 to 100. |
| Limits | `SENSOR_OUTBOX_MAX_BYTES`, `SENSOR_OUTBOX_MAX_AGE` | `1GiB`, `168h` | Outbox disk cap and age. |
| Limits | `SENSOR_NUCLEI_MAX_RATE_LIMIT`, `SENSOR_NUCLEI_MAX_CONCURRENCY`, `SENSOR_NUCLEI_MAX_BULK_SIZE` | 150, 25, 25 | The operator's ceilings for nuclei. |
| Safety | `SENSOR_SANDBOX_NETWORK` | `auto` | `required` refuses to start without network confinement. |
| Shutdown | `SENSOR_DRAIN_GRACE` | `30s` | How long running jobs may finish on stop. Keep `--stop-timeout` above it. |

Container limits (`--memory`, `--cpus`) work as usual; the sensor sizes its
job slots from what it sees.

## Capabilities and seccomp

- Run with `--cap-drop ALL`. Add `--cap-add NET_RAW` only if you want naabu
  SYN port scans; without it naabu uses connect scans.
- The seccomp profile lets the sensor confine each scan's network. Print the
  profile of the image you run: `docker run --rm ghcr.io/openctemio/sensor:<version>
  seccomp-profile > openctem-sensor-seccomp.json`, and pass it with
  `--security-opt seccomp=...`. Do not use `--privileged` or
  `seccomp=unconfined`.
- `--read-only` with `--tmpfs /tmp` is supported; the data volume is the only
  writable mount besides `/tmp`.
- Never mount the Docker socket into the sensor.

## Upgrade

```bash
docker pull ghcr.io/openctemio/sensor:v0.30.0
docker run --rm ghcr.io/openctemio/sensor:v0.30.0 seccomp-profile > openctem-sensor-seccomp.json
docker rm -f openctem-sensor
# run the same docker run command with the new tag and the same volume
```

With Compose: change the tag, then `docker compose pull && docker compose up -d`.
The identity, the outbox and the content cache carry over, and the sensor
does not pair again. Read the release notes first.

## Size the host and keep it to itself

The sensor's tools need CPU, memory and disk I/O the moment they start. On a
host shared with other heavy programs, a tool can wait so long for a CPU or
the disk that it cannot finish starting.

- **Do not run CI runners, build agents, databases or other scanners on a
  sensor host.** Their bursts take the CPU and the disk exactly when a scan
  starts.
- The sensor measures this (CPU, memory and I/O stall). While the host is
  overloaded it starts no new tool (one keeps running so work still moves),
  takes no new jobs, waits longer for a tool to start, and tries a starved
  start once more instead of failing it. The platform then hands work to
  less loaded sensors. The sensor's page shows the host pressure and warns
  when other programs use most of the host's CPU.
- If you must share the host, cap the other workload (lower priority with
  `nice -n 10`, a CPU and memory limit) and give the sensor container its own
  `cpus` and `mem_limit`.

Sizing, per job running at the same time, plus 1 vCPU and 1 GiB for the
sensor itself:

| Tools | vCPU | Memory |
|---|---|---|
| subfinder, dnsx, rdap, asn (light) | 0.5 | 256 MiB |
| httpx, katana | 1 | 1 GiB |
| nuclei | 2 | 2 GiB |
| naabu | 1 | 512 MiB, and a packet rate the network allows |
| trivy, betterleaks | 2 | 2 GiB |
| opengrep, semgrep, codeql | 2 to 4 | 4 to 8 GiB |

Example: an attack-surface sensor running two nuclei jobs and four light jobs
at once needs about 7 vCPU and 6 GiB. `SENSOR_MAX_JOBS` caps the jobs.

Each tool task runs in a resource envelope from its `resources.profile`
(light, standard, heavy). Where the sensor's cgroup is delegated to it
(systemd `Delegate=yes`, or a container whose main process is the sensor
and whose cgroup mount is writable), every task gets a cgroup of its own with
CPU, memory and process limits; otherwise the sensor uses rlimits and lower
priorities, and the container's `cpus` and `mem_limit` bound the whole
sensor. `SENSOR_TOOL_CGROUPS=off` turns the per-task cgroups off.

## Several sensors on one host

Use [`deploy/multi/`](../deploy/multi/README.md): one directory, one Compose
file, one service per sensor. Each sensor gets its own env file (platform URL
and pairing code), its **own data volume**, its own network and its own
policy directory; the release (`SENSOR_VERSION` in `.env`) and the hardening
are set once for all of them, and `./sensors.sh upgrade vX.Y.Z` moves every
sensor to a new release after checking the image signature.

```bash
./sensors.sh add acme --api-url https://openctem.example.com --pairing-code XXXX-XXXX
./sensors.sh up
```

Never share a volume or copy one: a second process on the same outbox refuses
to start, and a cloned identity is flagged `identity_cloned`. One sensor that
takes jobs of every organization is a [shared sensor](https://docs.openctem.io/sensors/shared-sensors/)
instead; the directory's README compares the setups.

## Kubernetes

Use the bundled sensor of the `openctem` Helm chart or the Deployment in
[Deploy on Kubernetes](https://docs.openctem.io/sensors/deploy-kubernetes/).
The pod runs as uid/gid 999 and needs `fsGroup: 999` on the persistent volume
(the chart sets it).

## Uninstall and re-pair

Uninstall:

1. In the console open the sensor and choose **Revoke access**.
2. `docker rm -f openctem-sensor && docker volume rm openctem-sensor-data`
   (a bind mount: delete the host directory).
3. Delete backups of the volume; they hold a revoked key.

Re-pair (lost or corrupted identity, or a moved host): create a new code under
**Expect a sensor**, remove the old volume (or run `pair -repair`, see
`openctemio-sensor -help`), and start the sensor with the new
`SENSOR_PAIRING_CODE`.

## Troubleshooting

### Permission denied on /var/lib/openctem

The container exits right after start:

```
Error: the sensor's data directory is not usable: mkdir /var/lib/openctem/content: permission denied
  path:               /var/lib/openctem/content
  owner of /var/lib/openctem: uid 1000, gid 1000 (mode 0755)
  the sensor runs as: uid 999, gid 999
```

You mounted a host directory that the sensor's user does not own. Either
`sudo chown -R 999:999 <host dir>` (1001 on a per-tool image, 65532 on the slim image), or use a named
volume (`-v openctem-sensor-data:/var/lib/openctem`). If the host directory
holds an older sensor's data, chown keeps it.

### Pairing failed

| The log says | Fix |
|---|---|
| A code is printed and nothing happens | An administrator must enter the code under **Pair a sensor** and approve it. Or start with `SENSOR_PAIRING_CODE`. |
| `The pairing request expired` | Nobody approved within 10 minutes; the sensor starts a new request. |
| `Rate limited ... HTTP 429` | Pairing starts are limited per address. Wait; avoid restart loops. |
| `x509: certificate signed by unknown authority` | The platform uses a private CA: mount it and set `SENSOR_CA_CERT_FILE`. |

### Clock skew (HTTP 401 on start)

`this machine's clock is 4h10m0s ahead of the platform's clock` or `HTTP 401
... Invalid credentials`: signatures allow 2 minutes of difference. Check
both hosts with `timedatectl` (`System clock synchronized: yes`) and `chronyc
tracking`; step the clock with `sudo chronyc makestep`.

### Cannot reach the API

`connection refused`, a timeout or a TLS error. From the sensor's host:
`curl -v https://openctem.example.com/health`. Check the firewall for the
platform port and the mTLS port, `HTTPS_PROXY`, and that `SENSOR_API_URL` is
the platform URL (not the web UI behind a proxy that strips `Authorization`).

### Low disk, the sensor stops claiming work

The sensor cleans up harder when less than 15% of the volume is free, and stops
claiming new jobs below 5% free (or 256 MiB, whichever is more). It reports
this on its heartbeat. Free space on the volume (`docker system df -v`, remove
unused images and volumes), or move `content/` and `workspaces/` to larger
storage with `SENSOR_CONTENT_DIR` and `SENSOR_WORKSPACE_DIR`.

### "Sensor host overloaded" in a task's log

A tool was held, or did not start in time and was tried once more, because
the host's CPU, memory or disk was stalled. The sensor's page shows which
(CPU, memory, I/O) and whether other programs on the host caused it. Move CI
runners and other heavy workloads off the host, or give the sensor more CPU
and memory (see [Size the host](#size-the-host-and-keep-it-to-itself)).

### Tools missing

`openctemio-sensor -list-tools` (run it with
`docker run --rm ghcr.io/openctemio/sensor:<version> -list-tools`) shows each
scanner and whether its binary is installed and passes its check. The image's
profile decides the tools ([PROFILES.md](PROFILES.md)): the default (standard)
image carries nuclei and the recon tools, the passive image only passive
discovery, the full image every tool; opengrep, semgrep, trivy and betterleaks
are also in their own images. A tool the local policy's `tools.allow`
does not list is disabled by choice.

### More

[Troubleshooting on the docs site](https://docs.openctem.io/sensors/troubleshooting/)
has the full table of messages and the setup checklist.
