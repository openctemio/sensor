# Sensor reference

The deployment and operations guide for the sensor is
**[docs.openctem.io/sensors](https://docs.openctem.io/sensors/)**: quick start,
Docker, Kubernetes and binary installs, pairing, confinement, upgrade,
back-up, security notes and troubleshooting. Start there.

This page is the detailed reference that used to be the README: every mode,
setting and safety mechanism of the sensor, kept next to the code. Where the
two differ, the docs site is current.

## Overview

The OpenCTEM sensor (`openctemio-sensor`) runs security tools close to what
they scan and reports the results to the OpenCTEM platform. It is usually run
as a long-lived daemon that the platform dispatches scans to; it can also run
a single scan and exit.

- **Tools**: nuclei and the recon tools (subfinder, dnsx, naabu, httpx,
  katana) in the default image; opengrep, semgrep, trivy and betterleaks in their own
  images or on the host; the passive lookups rdap and asn compiled into
  every build.
- **Modes**: daemon (server-controlled), one job (Kubernetes Job), one-shot
  and standalone. See [Modes](#modes).
- **Safety**: an SSRF guard on every target, a tool sandbox, a sensor-local
  policy the platform cannot change, signed custom templates and rate
  ceilings. See [Scanner safety model](#scanner-safety-model).
- **CI/CD**: CI scanning lives in [openctemio/ci](https://github.com/openctemio/ci)
  (`openctem-ci`, the `ghcr.io/openctemio/ci-<tool>` images, the GitHub
  Action and reusable workflow, and the GitLab templates). They report with
  the CI job's OIDC identity (no stored API key).

## Supported tools

| Tool | Category | Description |
|------|----------|-------------|
| Nuclei | DAST | Template-based vulnerability scanning |
| Nuclei (validate) | Validation | Non-destructive re-verification of a finding's own template (CTEM Stage 4) |
| Subfinder | Recon | Passive subdomain enumeration |
| DNSx | Recon | DNS resolution and records |
| Naabu | Recon | Port scanning (TCP connect) |
| HTTPx | Recon | HTTP/TLS probing and fingerprinting |
| Katana | Recon | Web crawling |
| Opengrep | SAST | Static code analysis with local rules only (no network) |
| Semgrep | SAST | Static code analysis |
| CodeQL | SAST | Code analysis when the `codeql` CLI is installed on the host (not in the images) |
| Trivy | SCA / IaC / container | `trivy` (filesystem), `trivy-config`, `trivy-image`, `trivy-full` |
| Betterleaks | Secrets | Secret detection (replaces gitleaks) |
| Reach probe | Network | Built in (`reach-probe`, capability `reach.probe@1`, daemon with commands). See [Reach probe](#reach-probe) |

How a recon task runs its targets: a task with several targets runs
httpx and naabu as one process over the whole list (`-l`), with the tool's
own concurrency and rate, so a host that does not answer costs only its own
probes, never a process start or a kill per target. httpx's per-request
`-timeout` comes from the platform's per-target budget (the budget shared by
the first try and the retries, at least 2 s), and each target counts as
finished the moment httpx prints its first line for it (the task's
progress); naabu's targets settle when it exits. A target httpx printed no
line for is listed as failed; one naabu printed nothing for (no open port)
has no result. When the job stops the run, the targets without a record are
unfinished. Single-target tasks, and subfinder, dnsx and katana, run once per
target.

A nuclei task over several hosts runs in up to 4 waves of whole hosts (every
target of one host, such as `203.0.113.5` and `203.0.113.5:8443`, in one
wave), one after the other. nuclei runs every template over every host and
reports no host as finished before its run ends, so each wave's findings are
delivered and its targets settle when the wave ends: the platform then
releases those hosts to the next tool of the pipeline while the later waves
run. Each extra wave loads the templates once more (a few seconds). A wave
that fails keeps the earlier waves' results; its targets and the later ones
are unfinished and the platform sends them again.

`openctemio-sensor -list-tools` lists the scanners and whether each binary is
installed on this host; `-check-tools` shows installation instructions and
`-install-tools` installs missing ones interactively.

## Install

### Container images

Images are published to `ghcr.io/openctemio/sensor` (mirrored to Docker Hub
as `openctemio/sensor`) as `<version>-<variant>` and `latest-<variant>`. The
`default` variant is also the plain tag: `sensor:<version>` and
`sensor:latest`.

| Variant | Tools | Default command |
|---|---|---|
| `default` | nuclei, subfinder, dnsx (and dnsx-enum, the same binary), naabu, httpx, katana | `-verbose` (the daemon with platform commands, the default mode; runs and reports every installed tool whose binary passes its check; the local policy's `tools.allow` narrows them) |
| `opengrep`, `semgrep`, `trivy`, `betterleaks`, `nuclei` | that tool | `-tool <tool> --help` (pass a command line) |

Every image is smoke-tested before it is published
(`scripts/image-smoke-test.sh`): each bundled tool must run and
`openctemio-sensor -list-tools` must report it `available`.

### Release archives

Archives for Linux, macOS and Windows are attached to each
[GitHub release](https://github.com/openctemio/sensor/releases) as
`openctemio-sensor_<version>_<os>_<arch>.tar.gz` (and `.zip`), where
`<version>` is the tag without the leading `v`:

```bash
VERSION=0.11.0   # a release tag without the leading v
curl -sSLO https://github.com/openctemio/sensor/releases/download/v${VERSION}/openctemio-sensor_${VERSION}_linux_amd64.tar.gz
tar xzf openctemio-sensor_${VERSION}_linux_amd64.tar.gz openctemio-sensor
sudo install -m 0755 openctemio-sensor /usr/local/bin/
openctemio-sensor -version
```

The archive holds only the sensor; the scanners it runs must be installed on
the host (`openctemio-sensor -check-tools`).

### From source

```bash
git clone https://github.com/openctemio/sensor.git
cd sensor
make build        # or: go build -o openctemio-sensor .
```

### Verifying images and releases

Release images are signed by digest with [cosign](https://docs.sigstore.dev/)
keyless signing: the signature's certificate names this repository's
`docker-publish.yml` workflow at the release tag, issued from GitHub's OIDC
token. No long-lived signing key exists. Check an image before you run it:

```bash
cosign verify ghcr.io/openctemio/sensor:v0.29.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml@refs/tags/v0.29.1
```

Release archives: `checksums.txt` is signed the same way by `release.yml`
(`checksums.txt.sigstore.json`):

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/openctemio/sensor/.github/workflows/release.yml@refs/tags/v0.29.1
sha256sum -c checksums.txt --ignore-missing
```

Images and archives published before signing was added carry no signature.

## Run a sensor for the platform

The default image runs the server-controlled daemon. It connects to the
platform, reports every scanner installed in the image (with versions) on its
heartbeat, and runs the scans the platform dispatches to it:

```bash
docker run -d --name openctem-sensor --restart unless-stopped \
  -e SENSOR_API_URL=https://openctem.example.com \
  -v openctem-sensor-data:/var/lib/openctem \
  ghcr.io/openctemio/sensor:v0.29.1
```

The same with Docker Compose:

```yaml
services:
  sensor:
    image: ghcr.io/openctemio/sensor:v0.29.1   # pin a release; never latest in production
    restart: unless-stopped
    # Hardened as in the platform's install snippet: read-only root
    # filesystem, no capabilities (add NET_RAW to cap_add only for naabu SYN
    # scans), no privilege escalation. The sensor and its tools write only
    # /tmp besides the data volume.
    read_only: true
    cap_drop: [ALL]
    # sensor-seccomp.json: docker/seccomp/sensor.json of the release you run.
    # It lets each scan task run in its own network namespace (confined).
    security_opt: ["no-new-privileges:true", "seccomp=./sensor-seccomp.json"]
    tmpfs: [/tmp]
    dns_search: .   # look names up exactly as written, no host search domain
    environment:
      SENSOR_API_URL: https://openctem.example.com
      # SENSOR_SANDBOX_NETWORK: required   # refuse to start unconfined (default auto)
      XDG_CONFIG_HOME: /tmp/.config
      XDG_CACHE_HOME: /tmp/.cache
      # SENSOR_CA_FINGERPRINT: <from the install snippet>
      # SENSOR_ALLOW_PRIVATE_TARGETS: "1"   # only to scan RFC 1918 / ULA addresses
    volumes:
      - data:/var/lib/openctem   # state/, outbox/, store/, content/ (keep it)
      # Recommended: keep the store's master key off the data volume.
      # - ./store-master.key:/run/secrets/sensor_store_key:ro   # 0600, owned by the sensor user
      # and set SENSOR_STORE_KEY_FILE: /run/secrets/sensor_store_key
    logging:
      driver: json-file
      options: {max-size: "50m", max-file: "5"}
volumes:
  data:
```

- **Keep the data volume.** One volume at `/var/lib/openctem` holds:
  - `state/`: the sensor's identity (its signing key, or the API key it
    renewed). Losing it means pairing again.
  - `outbox/`: every result is written here before it is sent and deleted
    only once the platform accepted it; without a volume, results still queued
    when the container is recreated are lost.
  - `store/`: the encrypted local store (the per-organization keys of the
    sealed outbox items, the job journal). It must be on the same volume as
    `outbox/`: an outbox restored without its store cannot be read.
  - `workspaces/`: per-job scratch directories, removed when the job ends and
    swept at start. Disposable.
  - `content/`: the scanner content cache (trivy DB, nuclei templates,
    semgrep rules). It can be deleted and is downloaded again.

  The sensor creates the three directories when they are missing (`state/`
  and `outbox/` 0700, owned by the sensor's user) and warns at start when
  `/var/lib/openctem` is not on a volume. Give each sensor its own volume; a
  second sensor on the same outbox refuses to start. See "Data volume" for
  backups, the older three-volume layout and moving the cache elsewhere.
- Without `SENSOR_API_URL` the daemon exits with code 2 and names the missing
  setting. Without `SENSOR_API_KEY` it pairs (below).
- The sensor detects its scanners at start-up and reports them on every
  heartbeat; the platform dispatches a scan only to sensors that report its
  tool installed. A tool is enabled when its wrapper is in this build and its
  binary passes the check (present, answers its version flag); rdap and asn
  are compiled in. Narrow them with the local policy's `tools.allow`.
  `SENSOR_TOOLS` (or `-tools`) is deprecated: for one release it still
  narrows the detected tools, with a warning and a `config.tools_deprecated`
  check; a listed tool that is not installed is ignored, never advertised.
- Code scanners (betterleaks, semgrep, trivy fs) get a repository asset's
  name, resolved inside `SENSOR_SCAN_ROOTS` (default: the working directory,
  `/scan` in the default image). Mount repositories there.
- A dispatched scan starts within one heartbeat (see
  [Heartbeat doorbell](#heartbeat-doorbell)).

### Pair the sensor

A sensor started without `SENSOR_API_KEY` pairs with the platform on first start
(api RFC-052). It creates its own Ed25519 key, never sends it, and prints:

```
Pair this sensor in OpenCTEM: Sensors > Pair a sensor
  Code:        K7QM-4ZTD
  Fingerprint: 512 · tiger · violet · anchor    (expires 10:42)
```

An administrator enters the code under **Sensors > Pair a sensor**, checks
that the console shows the same fingerprint (and the host and source address
it expects), confirms that the fingerprint matches, re-authenticates and
approves. The sensor then signs every request with its key; nothing secret is
typed or pasted. With Docker, read the code with `docker logs openctem-sensor`.

- `openctemio-sensor pair` pairs and exits (for a host prepared before the
  daemon runs); `openctemio-sensor pair <CODE>` attaches to a code an
  administrator created with **Expect a sensor** and prints the fingerprint
  to compare in the console.
- `openctemio-sensor pair -repair` replaces a lost or compromised key of a
  paired sensor; an administrator approves it again and the old key is
  revoked.
- The identity lives in `<state dir>/identity/` (`signing.key`,
  `identity.json`): 0600 files in a 0700 directory owned by the sensor's
  user. Looser permissions stop the sensor with the exact `chmod`/`chown` to
  run.
- Pairing pins the platform's TLS identity: the key of the trust anchor of
  the chain the sensor verified is stored in `identity.json`
  (`platform_tls_pin`), and every later platform request (v2, the v3 HTTPS
  binding, certificate requests) must reach the same anchor, with no fallback
  to the trust store. A TLS-inspecting proxy or a certificate from another CA
  is refused ("platform certificate does not match the pin stored at
  pairing"); re-pair, or set `SENSOR_CA_FINGERPRINT`, after a deliberate CA
  change. A sensor paired before this release is not pinned until it is
  paired again or sets `SENSOR_CA_FINGERPRINT`.
- The install snippet may carry `SENSOR_CA_FINGERPRINT` (the SHA-256 of the
  platform CA the sensor must see in the TLS chain; it overrides the pin
  stored at pairing) and `SENSOR_PLATFORM_KEY` (the thumbprint of the
  platform's pairing key). Both are public values that stop a fake platform
  at first contact. With `SENSOR_CA_FINGERPRINT`, `SENSOR_API_URL` must name the
  platform by the host name in its certificate, not by an IP address
  (`pair` refuses an IP URL; the daemon warns in its config report).
- Pairing also pins the platform job signer's keys the hello lists
  (`job_signing_keys` in `identity.json`). Such a sensor runs only commands
  the separate job signer signed for it. See [Signed jobs](#signed-jobs).
- An approved sensor starts as **New**: passive work only, no credentials,
  until an administrator promotes it.
- A sensor can still use a bearer API key (`SENSOR_API_KEY`, created under
  Settings > Sensors). See [API key renewal](#api-key-renewal).

### From an API key to a key-bound identity

A sensor started with `SENSOR_API_KEY` moves to a key-bound identity by itself when
the platform offers it (hello feature `key_bind`, api RFC-052 §4.8):

- At start it makes its own Ed25519 key in `<state dir>/identity/`, proves
  it holds it, and binds it with one call authenticated by the API key. The
  platform retires the API key in the same step; the sensor keeps its id,
  organization, grant and history, and signs every request from then on
  (and can use protocol v3, see `SENSOR_TRANSPORT`).
- One way: from then on the identity wins over `SENSOR_API_KEY` (the sensor warns;
  remove `SENSOR_API_KEY` from its configuration). Back up the state directory: it
  now holds the sensor's only credential. A lost identity means pairing the
  sensor again (an administrator creates a re-pair code for it).
- If the organization requires an administrator to approve sensor keys, the
  bind is refused and the sensor keeps its API key; re-pair it from the
  console instead.
- `SENSOR_KEY_BIND=off` keeps the API key.

## Modes

| Mode | Command | What it does |
|---|---|---|
| Daemon | no mode flag (the default) | Long-running, server-controlled: heartbeats, claims the commands the platform dispatches, delivers results through the outbox |
| One job | `-job <command id>` | Runs one platform command and exits (a Kubernetes Job). See [One job, then exit](#one-job-then-exit-kubernetes-job) |
| One-shot | `-tool <tool>` / `-tools a,b` with `-target` / `-push` (or `-json`, `-output`, `-daemon=false`, or `CI=true`) | Runs the scanners on `-target` once and pushes the results (needs `SENSOR_API_URL` and `SENSOR_API_KEY`) |
| Standalone | `-standalone -tool <tool>` | Runs locally and never contacts the platform; prints a summary, or with `-json` the CTIS reports (to stdout, or to `-output <file>`) |

The daemon takes platform commands by default. With
`-enable-commands=false`, `sensor.enable_commands: false` or `-standalone` it
runs scheduled scans only of the targets you configure (`targets:` in the
config file). `-daemon` and `-enable-commands` still work for one release,
with a deprecation warning; `-enable-recon`, `-enable-vulnscan`,
`-enable-secrets`, `-enable-assets`, `-enable-pipeline` and
`-bootstrap-token` are ignored with a warning (capabilities follow the
installed tools). The former `-platform` mode was removed; the flag is
refused with a message naming the daemon.

```bash
# One scan, results pushed to the platform
openctemio-sensor -tool semgrep -target ./src -push

# Several scanners
openctemio-sensor -tools semgrep,betterleaks,trivy -target . -push -verbose

# Local only, results to a file
openctemio-sensor -standalone -tool betterleaks -target . -json -output results.json

# Daemon with a config file
openctemio-sensor -config sensor.yaml
```

In a container, arguments replace the image's default command. Use the
image that carries the tool:

```bash
docker run --rm -v "$(pwd)":/scan -w /scan \
  -e SENSOR_API_URL=https://openctem.example.com -e SENSOR_API_KEY \
  ghcr.io/openctemio/sensor:latest-semgrep -tool semgrep -target /scan -push
```

A one-shot run whose key is rejected exits with code **78** (`EX_CONFIG`);
see [Rejected key and connection failures](#rejected-key-and-connection-failures).

## Connecting to the platform

### Which URL

`SENSOR_API_URL` is the **API** base URL, the address whose `/health` answers
`{"status":"healthy"}`. It is not the web UI: the UI's `/api/v1` proxy does
not forward the sensor's credentials, and a current UI answers sensor
requests with `421 WRONG_ENDPOINT`.

The sensor reaches a platform on loopback, a private network, a Docker
network name (`http://api:8080`) or a Kubernetes service name without any
extra setting. Only cloud-metadata and link-local addresses are refused. The
`OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE` / `..._ALLOW_LOOPBACK` workarounds that
the agent release needed are no longer required; remove them, because they
also widen what scan targets may reach.

A plain `http://` URL to anything but loopback works but prints a warning that
credentials are sent in clear text. Use `https://` outside a private network.

### HTTPS with a private CA

The images run as the non-root user `openctem`, so `update-ca-certificates`
cannot run inside them. Any of these make the sensor trust your CA:

| Method | Example |
|---|---|
| `SENSOR_CA_CERT_FILE` (platform and content downloads only) | `-v /path/ca.pem:/certs/ca.pem:ro -e SENSOR_CA_CERT_FILE=/certs/ca.pem` |
| Mount the CA into `/etc/ssl/certs` (everything, scanners included) | `-v /path/ca.pem:/etc/ssl/certs/my-ca.pem:ro` |
| `SSL_CERT_DIR` | `-v /path/ca.pem:/certs/my-ca.pem:ro -e SSL_CERT_DIR=/certs` |
| `SSL_CERT_FILE` | `-v /path/ca.pem:/certs/my-ca.pem:ro -e SSL_CERT_FILE=/certs/my-ca.pem` |

The public CAs keep working with each of these. Mounting into
`/usr/local/share/ca-certificates/` does **not** work (it needs
`update-ca-certificates`). Without the CA the sensor logs
`x509: certificate signed by unknown authority` and keeps retrying. In
Kubernetes, mount the CA from a ConfigMap at `/etc/ssl/certs/<name>.pem` with
`subPath`.

### Through an HTTP proxy

A sensor has three kinds of outbound traffic, each with its own setting
(api RFC-034):

| Traffic | Setting | When unset |
|---|---|---|
| To the platform | `SENSOR_CONTROL_PROXY` (a proxy URL, or `direct`) | `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` |
| Content and feeds (nuclei templates, semgrep rules, trivy's database, KEV/EPSS) | `SENSOR_CONTENT_PROXY` (a proxy URL, or `direct`) | the platform setting above |
| Scanners to their targets | `SENSOR_SCAN_PROXY`: `inherit` or `direct` | `inherit` |

- Proxy URLs may be `http://`, `https://`, `socks5://` or `socks5h://`, with
  `user:password@` when the proxy needs authentication. `NO_PROXY` is the
  bypass list. An `https://` platform is reached through an HTTP proxy with a
  `CONNECT` tunnel, so TLS stays end to end.
- The usual setup sends everything outbound through one proxy:
  `-e HTTPS_PROXY=http://proxy.example.com:3128 -e NO_PROXY=openctem.example.com,.svc`.
- With `inherit` (the default), scanner processes get the same
  `HTTP(S)_PROXY` and `NO_PROXY`, and the sensor prints a warning at start:
  their traffic to targets then goes through the proxy unless `NO_PROXY`
  lists the target, which is rarely wanted for internal targets. Set
  `SENSOR_SCAN_PROXY=direct` so scanners connect directly (content downloads
  keep using the proxy), or `SENSOR_SCAN_PROXY=inherit` to keep the
  inheritance on purpose (the warning stops).
- Content downloads check the target address **before** they use the proxy,
  so the proxy cannot be used to reach private or cloud-metadata addresses.
- For a TLS-inspecting proxy, mount its CA and set `SENSOR_CA_CERT_FILE`. It
  is trusted for the platform and for content downloads; scanner processes
  read `SSL_CERT_FILE`.

### Organization proxy pools

An organization can send a sensor's scan traffic through its own proxies:
an administrator pastes a list of proxies into the console, and the
platform puts the pool on each scan or retest command for the sensor that
claims it. The pool is not a scanner setting: it is the Dial hook of each
task's forwarder, so it carries every connection of a confined tool, with
no tool flag and no credential in a tool's arguments or environment. The
forwarder still checks each destination against the job's scope, pins its
address and applies the per-target rate first; the pool only chooses the
path. A pooled job never goes direct: a connection fails (and is reported)
rather than fall back. A pool sent as the organization's default applies
to public targets only; private targets are dialed directly as before.

The sensor reports the capability `egress.upstream@1` only when its tools
run out of process in a sandbox that confines their network (it also
reports `net.confined@1`) and its owner accepts pools; the platform sends a
sensor whose pool is set no scan without it.

A sensor with `SENSOR_SCAN_EGRESS=direct-only` reports `egress.host-direct@1`
(not on a shared sensor): the platform runs its scans direct, and the console
shows its network path as "Direct (set on the sensor host)" rather than as a
sensor to upgrade. The platform holds its jobs only when the organization
requires a proxy.

Validate jobs (finding re-checks) go through the same pool as the scans, so a
re-check comes from the address the scan came from: the sensor reports
`egress.validate@1` next to `egress.upstream@1` when it serves commands. The
safe-check's connection and the nuclei re-verification leave through the pool;
if the pool cannot carry the probe (proxy down, wrong credentials, a ruleset
that refuses the target), the job ends inconclusive or fails, and the finding
is never marked fixed on the strength of a proxy failure. A probe never goes
direct.

The console's Test button for a pool is served as a `proxy_test` command
(capability `proxy.test@1`, on every sensor that accepts pools): the sensor
tests each endpoint through the platform's echo and reports the exit address,
handshake time, IPv4 and IPv6, and whether the proxy only allows port 443. The
request through the proxy carries a one-test token and nothing else.

| Setting | Values | Default |
|---|---|---|
| `SENSOR_SCAN_EGRESS` | `platform`: accept the pool a job carries; `direct-only`: refuse every pooled job (`egress_refused_by_host`), do not report `egress.upstream@1` and report `egress.host-direct@1` instead | `platform` |
| `SENSOR_SCAN_EGRESS_ALLOW` | Comma list of `host:port` (or `host`, any port) proxies this sensor accepts; a job naming another is refused (`egress_refused_by_host`) | any endpoint that passes validation |

A bad value stops the sensor at start (exit code 2). Endpoints are checked
whatever the list says: loopback, link-local, cloud metadata, multicast and
reserved addresses are refused, also when a host name resolves to one at
dial time.

Which built-in tools go through the pool:

| Tool | Through the pool | Notes |
|---|---|---|
| nuclei, httpx, katana | yes | every request to a target |
| naabu (connect scan, the default) | yes | each probed port is a tunnel; see the CONNECT note below |
| naabu SYN scan | no: the job is refused | raw packets never pass the forwarder (`egress_unavailable`) |
| subfinder | yes, for its passive sources | names are resolved by the forwarder on the sensor, not through the proxy |
| dnsx | no proxy involved | DNS only: the forwarder answers A/AAAA itself and asks the sensor's resolvers for other record types; DNS is never proxied |
| trivy, semgrep, codeql (registry and rule downloads), asn and rdap lookups | yes | their vendor and registry hosts are public, so a default pool carries them |
| betterleaks, opengrep | nothing to carry | network `none`: they run as usual |
| scanner content (templates, databases) and code-scan source fetches | no | the sensor's content path (`SENSOR_CONTENT_PROXY`), not scan traffic |
| UDP | no | the forwarder carries TCP only |

- A pooled job is refused (`egress_unavailable`) where its tools would not
  run behind the forwarder: `SENSOR_TOOL_RUNTIME=in-process`, a sandbox
  without network confinement (`SENSOR_SANDBOX_NETWORK`), CI/runner mode
  (tools run unconfined), and a shared sensor (`egress_refused_by_host`).
- HTTP CONNECT proxies must allow CONNECT to the ports you scan: many allow
  only 443 by default, which turns a port scan or a plain-HTTP target into
  refusals. SOCKS5 proxies have no such limit.
- At the end of each pooled job the sensor reports, per endpoint, the
  tunnels that worked and the failures by class (`proxy_down`,
  `proxy_auth`, `target_unreachable`, `target_refused`) and the handshake
  times; the platform turns them into the endpoint's health. Inside one job
  the sensor stops using an endpoint that is down for a while (30 s,
  doubling to 10 min) and never again one that refused its credentials.

### Network report

The sensor tells the platform where it sits, so jobs go to a sensor that can
reach their targets. The manifest carries a network report: what the host
owner declares (`SENSOR_NETWORK_SITE`, `SENSOR_NETWORK_REACH`,
`SENSOR_NETWORK_DNS_SUFFIXES`, `SENSOR_INTERNET`) and what the sensor detects
(on-link prefixes, default routes, resolvers, the egress address the platform
saw). It is re-checked every 5 minutes.

- The report is never wider than the [local policy](#sensor-local-policy): a
  prefix outside `targets.allow`, inside `targets.deny`, or private on a sensor
  that may not scan private targets is left out.
- `SENSOR_NETWORK_REPORT`: `summary` (default: private prefixes listed, public
  ones counted), `full`, or `off` (only a fingerprint and the internet mode).
- Detection reads local tables only; its one network call is the platform's
  egress echo. A value the sensor cannot use stops it at start.
- The report only narrows routing: it never gives the sensor work its scope
  and zones do not.

Settings: [docs.openctem.io/sensors/settings](https://docs.openctem.io/sensors/settings/#SENSOR_NETWORK_SITE).

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENSOR_API_URL` | Backend API base URL (or `-api-url` flag) | - |
| `SENSOR_API_KEY` | Legacy bearer API key (or `-api-key` flag). Unset: the sensor [pairs](#pair-the-sensor) and signs its requests with its own key | - |
| `SENSOR_ID` | Sensor identifier (or `-sensor-id` flag) | auto |
| `SENSOR_INSTANCE_ENROLLMENT_TOKEN` | Single-use instance enrollment token (`octe_…`) a super administrator issued (or the install registered for its bundled sensor): a sensor with no identity pairs with it and is enrolled as a shared sensor of the instance, without a further approval; not with `SENSOR_PAIRING_CODE`; ignored once paired; never logged | - |
| `SENSOR_PAIRING_CODE` | Pairing code an administrator created with "expect a sensor" (`XXXX-XXXX`): a sensor with no identity attaches to it on first start; ignored once paired; never logged | - (the sensor prints a code) |
| `SENSOR_TOOLS` | Deprecated. One-shot: the scanners to run. Daemon: only narrows the detected tools (not-installed entries are ignored); use the local policy's `tools.allow` | - (every installed tool) |
| `SENSOR_SHARED_MODE` | `1` (or `-shared`): [shared mode](#shared-mode-a-sensor-that-runs-jobs-of-many-tenants), for a sensor that runs jobs of many tenants | `0` |
| `SENSOR_ADAPTER_DIRS` | Directories of operator-installed tools (each a `tool.yaml` with its program), `:`-separated | - |
| `SENSOR_NAME` | Platform-mode sensor name (or `-name` flag) | auto |
| `SENSOR_MAX_JOBS` | Cap on commands run at once, 1-100 (or `-max-concurrent`, `sensor.max_jobs`); the live count follows CPU, memory and tool costs | no cap |
| `SENSOR_DRAIN_GRACE` | On SIGTERM, how long running scans may finish before they are stopped and handed back to the platform (allow it plus ~15 s in `stop_grace_period` / `terminationGracePeriodSeconds`) | `30s` |
| `SENSOR_STATE_DIR` | Local state: the paired identity (`identity/`), the renewed API key (`sensor-credentials.json`, see "API key renewal"), the tool cost history (`tool-costs.json`) and the lookup cache (`lookup-cache/`: the IANA RDAP bootstrap file and the IPtoASN dataset, public data only). Mount a persistent volume | `/var/lib/openctem/state` when writable, else `~/.openctem` |
| `SENSOR_PROTOCOL` | Sensor protocol (or `-protocol`, `server.protocol`): `auto` or `v2`, which are the same; `v1` is retired and refused | `auto` |
| `SENSOR_KEY_BIND` | `auto`: a sensor started with `SENSOR_API_KEY` binds its own signing key when the platform offers it and stops using the API key (one way, see [From an API key to a key-bound identity](#from-an-api-key-to-a-key-bound-identity)); `off`: keep the API key | `auto` |
| `SENSOR_TRANSPORT` | Transport of sensor protocol v3 for a paired sensor: `auto` (gRPC over mutual TLS, then HTTPS where gRPC is blocked, then protocol v2 on a platform without v3), or force `grpc`, `https` or `v2`. An identity refusal never falls back. The client certificate and the pinned platform CA are kept in `identity/` | `auto` |
| `SENSOR_CA_CERT_FILE` | PEM file with the platform's private CA (or a TLS-inspecting proxy's CA), trusted for platform requests and content downloads | - |
| `SENSOR_CA_FINGERPRINT` | SHA-256 fingerprint of the platform's CA certificate (from the install snippet); pins platform TLS to it. `SENSOR_API_URL` must then use a host name | - |
| `SENSOR_PLATFORM_KEY` | Thumbprint of the platform's pairing key (from the install snippet); pairing refuses another key | - |
| `SENSOR_REQUIRE_LOCAL_POLICY` | `true`: without a local policy, refuse every job with network targets, custom templates or callbacks; `false`: the older behavior. See [Without a policy](LOCAL_POLICY.md#without-a-policy) | `true` for a sensor paired by this release or later, else `false` |
| `SENSOR_JOB_SIGNING_KEYS` | The platform job signer's keys, comma-separated: key ids (`SHA256:<hex>`, from `openctem-signer pubkey`; the public key then comes from the platform's hello) or base64 Ed25519 public keys. Added to the keys pinned at pairing. With a key pinned, every signed job is verified before it runs. Needs a paired sensor. See [Signed jobs](#signed-jobs) | the keys pinned at pairing |
| `SENSOR_JOB_SIGNING_ROOT` | The installation's offline job-signing root: its key id (`SHA256:<hex>`, printed by `openctem-signer root keygen`) or base64 Ed25519 public key. Signer keys are then taken from the root-signed key set the platform serves, so they rotate without pairing again. Overrides the root pinned at pairing. See [Signed jobs](#signed-jobs) | the root pinned at pairing |
| `SENSOR_REQUIRE_SIGNED_JOBS` | `true`: refuse every command without a valid job signature (refusal rule `job_signature`); `false`: run unsigned commands, still verify signed ones. `true` without a pinned key stops the sensor at start. See [Signed jobs](#signed-jobs) | `true` when pairing pinned signer keys, else `false` |
| `SENSOR_KEY_AUTORENEW` | API key auto-renewal (or `-key-autorenew`): `true`, `false`, or unset. See [API key renewal](#api-key-renewal) | on when the state directory persists |
| `SENSOR_CONTROL_PROXY`, `SENSOR_CONTENT_PROXY`, `SENSOR_SCAN_PROXY` | Outbound proxies. See [Through an HTTP proxy](#through-an-http-proxy) | - |
| `SENSOR_SCAN_EGRESS`, `SENSOR_SCAN_EGRESS_ALLOW` | The organization proxy pools a job may carry. See [Organization proxy pools](#organization-proxy-pools) | `platform`, any valid endpoint |
| `SENSOR_REGION` | Deployment region (or `-region` flag; `AWS_REGION` is also read) | `default` |
| `SENSOR_JOB_ID` | Run one platform command and exit (or `-job`). See [One job, then exit](#one-job-then-exit-kubernetes-job) | - |
| `SENSOR_SCANNER_PRIORITY` | Priority of scanner processes: `low` (nice +10, lowest best-effort I/O, OOM-killed before the sensor) or `normal` | `low` |
| `SENSOR_TOOL_CGROUPS` | Per-task cgroup limits (CPU, memory, processes from each tool's `resources.profile`) where the sensor's cgroup is delegated: `auto`, or `off` for rlimits only | `auto` |
| `SENSOR_PROTECT_FROM_OOM` | `true` protects the sensor process itself from the OOM killer (Linux; needs `CAP_SYS_RESOURCE`) | `false` |
| `SENSOR_TOOL_RUNTIME` | How the tools ported to the tool contract (sdk-go `pkg/tool`) run: `out-of-process` (the sensor re-executes itself per task in the tool sandbox) or `in-process` (rollback) | `out-of-process` |
| `SENSOR_ALLOW_PRIVATE_TARGETS` | Set `1` to allow scanning RFC1918 / IPv6 ULA targets. IMDS / loopback / CGNAT stay blocked regardless. See [Scanner safety model](#scanner-safety-model). | off |
| `SENSOR_SCAN_ROOTS` | Directories (`:`-separated) that filesystem targets of dispatched code scans (betterleaks, semgrep, trivy fs) must resolve inside; a relative target is taken relative to the first. See [Scanner safety model](#scanner-safety-model). | the sensor's working directory (`/scan` in the images) |
| `SENSOR_TEMPLATE_SIGNING_KEYS` | Only for a sensor that does **not** verify [signed jobs](#signed-jobs): the platform's template-signing public keys for this sensor's tenant (base64 Ed25519, comma-separated; from `GET /api/v1/scanner-templates/signing-key`). Custom templates in a scan run only with a signature one of them verifies. A sensor that verifies signed jobs trusts custom templates through the signed job and does not need it. This fallback will be removed. See [Nuclei template trust](#nuclei-template-trust-and-rate-limits). | none: without signed jobs, scans with custom templates fail |
| `SENSOR_LOCAL_POLICY` | The sensor-local policy file (or `-local-policy`): targets, ports, tools, job types, custom templates, interactsh, rate and a kill switch, set by the network owner; jobs outside it are refused whatever the platform sends. A policy that cannot be loaded stops the sensor. See [Sensor-local policy](#sensor-local-policy). | `/etc/openctem/sensor-policy.yaml` when it exists, else none |
| `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` | Shorthand policy without a file: `targets.allow` (comma-separated CIDRs, IPs, names, `*.domain`) and `ports.allow` (`80,443,8000-8999`) | - |
| `SENSOR_KILL_SWITCH_FILE` | While this file exists the sensor runs no job and heartbeats "paused by local policy" (also `kill_switch_file` in the policy) | - |
| `SENSOR_DNS_RESOLVERS` | DNS resolvers dnsx, naabu and subfinder use (comma-separated IP or IP:port). Unset: the nameservers in `/etc/resolv.conf`, as httpx, katana and nuclei use. The tools' built-in public resolver lists are never used, so enumerated names do not go to third-party resolvers and internal or split-horizon names resolve. An invalid value fails recon jobs | `/etc/resolv.conf` |
| `SENSOR_SANDBOX` | How every tool run is confined (see [Tool sandbox](#tool-sandbox)): `auto` enforces what the host supports and logs the rest, `required` refuses to start unless every control is enforced, `off` runs tools as plain child processes. One-shot runs sandbox only when this is set | `auto` (daemon), `off` (one-shot) |
| `SENSOR_NUCLEI_MAX_RATE_LIMIT` | Ceiling on nuclei requests per second (`-rate-limit`). A scan may ask for less, never more | `150` |
| `SENSOR_NUCLEI_MAX_CONCURRENCY` | Ceiling on nuclei templates in parallel (`-c`) | `25` |
| `SENSOR_NUCLEI_MAX_BULK_SIZE` | Ceiling on nuclei hosts in parallel per template (`-bs`) | `25` |

Every setting is `SENSOR_`-prefixed. The sensor refuses to start while a
removed name is set, naming its replacement: `API_URL` (`SENSOR_API_URL`),
`API_KEY` (`SENSOR_API_KEY`), `REGION` (`SENSOR_REGION`),
`PLATFORM_KEY_AUTORENEW` (`SENSOR_KEY_AUTORENEW`), `AGENT_ID`, `AGENT_NAME`,
`AGENT_ALLOW_PRIVATE_TARGETS` and `OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS`
(`SENSOR_ALLOW_PRIVATE_TARGETS`, the one switch for private scan targets).
The `-agent-id` flag still works.

### Config File (sensor.yaml)

`-config` reads the keys of `Config` in `main.go`: `sensor:`, `server:`,
`outbox:`, `retry_queue:` (deprecated), `scanners:`, `collectors:` and
`targets:`.

```yaml
sensor:
  name: production-scanner
  region: default
  heartbeat_interval: 1m
  enable_commands: true
  command_poll_interval: 30s   # used only with an API without the heartbeat doorbell
  # disable_doorbell: true     # poll every command_poll_interval regardless
  # max_jobs: 8                # cap on commands run at once, 1-100 (SENSOR_MAX_JOBS); unset: follow CPU/memory

server:
  base_url: https://openctem.example.com
  api_key: ${SENSOR_API_KEY}
  sensor_id: your-sensor-id
  timeout: 30s
  protocol: auto               # auto | v2, the same (SENSOR_PROTOCOL; v1 is refused)

outbox:                        # undelivered results; on by default in the daemon
  dir: /var/lib/openctem/outbox
  max_bytes: 1GiB
  max_age: 168h

scanners:
  - name: semgrep
    enabled: true
  - name: betterleaks
    enabled: true

targets:
  - /path/to/project
```

### Heartbeat doorbell

With an API that supports it (RFC-023 §9.2a) the daemon's heartbeat answer
says when there is work, and the daemon polls only then:

| Heartbeat answer | Sensor |
|---|---|
| `pending_jobs > 0` | polls for commands immediately |
| `next_heartbeat_seconds` | next heartbeat after that long (5 s – 5 min) |
| hints present | no fixed 30 s poll; a safety poll every 5 min |
| no hints (older API) | polls every `command_poll_interval`, as before |
| `pause` (sensor disabled) | takes no new jobs, running jobs finish, keeps heartbeating; logs `paused by platform`; resumes on the first heartbeat without `pause` |
| `drain` | like `pause`, until restart |
| `rotate_key` | renews the key now (when key auto-renewal is on, see "API key renewal"), saving it to the credentials file |
| `update`, unknown | logged only |

### Data volume

The sensor keeps everything it must not lose under `/var/lib/openctem`:

| Directory | Holds | Setting to move it |
|---|---|---|
| `state/` | identity (signing key, sensor ID), renewed API key, tool cost history | `SENSOR_STATE_DIR` |
| `outbox/` | results not yet accepted by the platform, the outbox key | `SENSOR_OUTBOX_DIR` |
| `store/` | encrypted local store: keys of the sealed outbox items, job journal, `master.key` | `SENSOR_STORE_DIR` |
| `workspaces/` | per-job scratch directories (disposable) | `SENSOR_WORKSPACE_DIR` |
| `content/` | scanner content cache (disposable) | `SENSOR_CONTENT_DIR` |

Mount one volume at `/var/lib/openctem`. The images declare no `VOLUME`
(an anonymous volume looks like a real mount and is lost with a new
container; one on a subdirectory would shadow that subdirectory of your
volume). The three settings are an advanced override, e.g. to keep the
content cache on other storage.

**Backups.** Back up the whole volume, or leave out the cache:

```bash
docker run --rm -v openctem-sensor-data:/data:ro -v "$PWD":/backup alpine \
  tar -C /data --exclude=./content -czf /backup/sensor-data.tgz .
```

The archive holds the sensor's private key: store it like a credential.

**Older installs (three volumes).** A sensor started with a volume on each
of `/var/lib/openctem/state`, `/outbox` and `/content` keeps working
unchanged. To move to one volume:

```bash
docker compose stop sensor          # or: docker stop openctem-sensor
docker volume create openctem-sensor-data
for d in state outbox content; do
  docker run --rm -v <old-$d-volume>:/from:ro -v openctem-sensor-data:/to alpine \
    sh -c "mkdir -p /to/$d && cp -a /from/. /to/$d/"
done
docker run --rm -v openctem-sensor-data:/to alpine sh -c 'chown "$(stat -c %u:%g /to/state)" /to'
# replace the three volume lines with: - openctem-sensor-data:/var/lib/openctem
#   (an external volume: volumes: {openctem-sensor-data: {external: true}})
docker compose up -d sensor
docker compose logs sensor | grep -E "transport|identity|Warning"
```

Check that the sensor starts with its existing identity (no new pairing
code, the same sensor on the platform's Sensors page and the same
`transport:` line in the log) before removing the old volumes; copying
`content` is optional (it is downloaded again).

### API key renewal

The daemon keeps its state in `SENSOR_STATE_DIR` (default
`/var/lib/openctem/state` when writable, else `~/.openctem`). A key it
renews is saved there (`sensor-credentials.json`, 0600, written atomically)
and used on the next start instead of `SENSOR_API_KEY`, because the renewal retires
the key the sensor was installed with. If `SENSOR_API_KEY` is changed to a key an
administrator regenerated, the new `SENSOR_API_KEY` wins. A file an earlier version
kept in `~/.openctem` is moved into the state directory.

Auto-renewal (`SENSOR_KEY_AUTORENEW`, `-key-autorenew`): `true` / `false`
force it; unset, it is **on when the state directory survives the container
being recreated** (outside a container always; inside one, only on a mounted
volume that is not a tmpfs) and off otherwise, with the reason in the start-up
log. **Mount the data volume at `/var/lib/openctem`** (the platform's install
snippets do; a directory counts by its nearest mount, so a volume on
`/var/lib/openctem/state` itself works too). The images create the
directories but declare no `VOLUME`: an anonymous volume is lost with the
container. The platform
issues expiring keys only when its `SENSOR_KEY_TTL` is set; with no TTL a
renewal (once, on the first start with renewal on) yields a key that never
expires and nothing else happens.

### Tool sandbox

Every scanner run by the daemon is confined before it starts (sdk-go
`pkg/sensorkit/executor`, the `process` backend). The sensor binary re-executes itself
as a launcher, confines that process, then replaces it with the tool:

- a private, throwaway directory (its HOME and TMPDIR), removed after the run;
- resource limits: memory, processes and threads (a fork bomb stops at its
  allowance), file size, open files, no core dumps;
- no privilege escalation (no_new_privs);
- **Landlock**: the tool writes only in its directory and the paths its
  wrapper declares (a report directory, nuclei's private configuration), and
  cannot read the sensor's credentials file, outbox and its key, local policy,
  `-config` file or a Tenable.sc connector configuration left from older
  releases;
- **seccomp**: ptrace, mount and namespaces, kernel modules, keyrings, bpf,
  perf and similar syscalls are refused;
- the sensor itself is non-dumpable, so a tool cannot read its memory or
  environment through `/proc`.

It needs no extra privileges and works under Docker's default seccomp profile
(Landlock needs Linux 5.13 or newer). At start the daemon logs `Tool sandbox:
auto; private task directory, rlimits, no_new_privs, landlock vN, seccomp true`
or a warning naming what the host does not support. Set
`SENSOR_SANDBOX=required` to refuse to start without all of it. The sensor
never uses a Docker socket.

### Shared mode (a sensor that runs jobs of many tenants)

A sensor an instance shares between organizations runs with `-shared` or
`SENSOR_SHARED_MODE=1`. The isolation profile is sdk-go's (`docs/SECURITY.md`
there, "Shared mode"); the sensor only switches it on:

- the tool sandbox and network confinement are required and a local policy
  must be loaded: without any of them the sensor refuses to start, before it
  pairs (`SENSOR_SANDBOX` and `SENSOR_SANDBOX_NETWORK` may only be unset or
  `required`);
- every tool runs out of process, in its sandbox: `SENSOR_TOOL_RUNTIME=in-process`
  is refused;
- each task has its own throwaway directory and no writable cache, output or
  configuration directory is shared between jobs. trivy writes its scan
  cache next to its vulnerability database, so a trivy task is refused in
  shared mode until the database can be mounted read-only into the task;
  the network tools (nuclei, httpx, subfinder, ...) are unaffected;
- private targets stay refused unless the operator allows them
  (`SENSOR_ALLOW_PRIVATE_TARGETS=1` and the local policy's
  `targets.allow_private`) **and** the zone ranges of the job's signed
  statement contain the address (an unsigned `zone_ranges` field is
  ignored; until signed statements carry zones, shared jobs reach public
  addresses only); loopback, link-local, cloud metadata and CGNAT addresses are
  never reached. Every address a task dials was checked for it (no DNS
  rebinding between the check and the connection);
- only signed jobs run: the statement must be signed for the instance scope
  and this sensor, and may belong to any organization. A job-signing root or
  key must be pinned (`SENSOR_JOB_SIGNING_ROOT` or `SENSOR_JOB_SIGNING_KEYS`).
  Every result is bound to the job's signed organization, and nothing is
  stored or sent for a job the sensor does not hold;
- the sensor advertises `shared.isolation@1`, and the platform sends shared
  jobs only to sensors that do.

### Results delivery and the outbox

**Protocol.** A paired sensor speaks protocol v3 (gRPC over mutual TLS, or
HTTPS where gRPC is blocked; see `SENSOR_TRANSPORT`) and falls back to
protocol v2 (`/api/v2/sensor/*`, api RFC-026 and RFC-029) on a platform
without v3, for everything: heartbeat, commands, suppressions, fingerprint
queries, key renewal and results. The platform retired protocol v1
(`/api/v1/agent/*`) in 2026-10, so the sensor needs an OpenCTEM API from
2026-10-02 on; against an older one every call fails with "the platform does
not serve sensor protocol v2". `SENSOR_PROTOCOL` / `-protocol` /
`server.protocol` is `auto` (default) or `v2`, which are the same; `v1` is
refused at start-up. The sensor is identified by its key alone.

**Outbox.** A daemon writes every result to its outbox **before** sending it
and deletes it only once the platform accepted it, so a crash, `kill -9`, an
API outage or a restart loses nothing; the backlog is sent, oldest first, as
soon as a heartbeat gets through. A command is reported complete only after
its results were accepted. Results the platform refuses for good (malformed,
tool not declared, ...) move to `dead/` with the reason instead of being
retried forever. The outbox never fills the disk: past the size or age cap the
oldest entries are dropped with a warning in the log, a metric and on the
heartbeat (the API stores it with the sensor).

| Setting | Default | |
|---|---|---|
| `SENSOR_OUTBOX` (`outbox.enabled`) | `on` for the daemon, `off` for one-shot runs | `on` keeps a one-shot run's results for its next run |
| `SENSOR_OUTBOX_DIR` / `-outbox-dir` (`outbox.dir`) | `/var/lib/openctem/outbox`, else `~/.openctem/outbox` | on the data volume (`/var/lib/openctem`) |
| `SENSOR_OUTBOX_MAX_BYTES` (`outbox.max_bytes`) | `1GiB` (and at most half of the free space) | e.g. `512MiB` |
| `SENSOR_OUTBOX_MAX_AGE` (`outbox.max_age`) | `168h` | age after which dead letters are deleted; a pending result is kept until the platform accepts or refuses it |
| `SENSOR_OUTBOX_KEY_FILE` (`outbox.key_file`) | `<dir>/outbox.key` | the AES-256-GCM key, created on first start; point it at a mounted secret to keep it off the data volume |

| `SENSOR_STORE_DIR` | `store/` next to the outbox directory | the encrypted local store; keep it on the same volume as the outbox |
| `SENSOR_STORE_KEY_FILE` | `<store dir>/master.key`, created on first start (0600) | the store's master key; point it at a mounted secret (a Docker/Kubernetes secret, mode 0600) so the key is not on the data volume. Never put the key in the image |
| `SENSOR_WORKSPACE_DIR` | `workspaces/` next to the outbox directory | per-job workspaces (0700), swept at start |

**Local store (sdk-go v0.36.0).** New outbox items are
sealed under a per-organization key held in the store. Items written by an
earlier sensor are still read: the existing `outbox.key` is adopted as the
organization sensor's data key, nothing is re-encrypted, and a fresh outbox no
longer creates `outbox.key`. At start the sensor reports every job its journal
shows unfinished as a failed result, sweeps leftover workspaces, and runs a
janitor. It claims no work while the outbox is full of unacknowledged results,
storage is at the high watermark or the volume is low. `doctor` checks the
store directory, key, disk and persistence.

**Upgrade and rollback.** Upgrading needs no action beyond keeping the one data
volume. Rolling back to a sensor without the store, once it has written
sealed items, refuses to start with `ErrStoreRequired` instead of losing them:
upgrade again, or let the queue drain before the rollback. Losing `store/` (or
the key file) makes sealed items unreadable; back up `store/` with the volume,
and keep the key secret's backup apart from it.

A full outbox (unacknowledged results at 85 % of `SENSOR_OUTBOX_MAX_BYTES`)
refuses new results instead of evicting queued ones. Files are 0600 in a 0700 directory and encrypted; one sensor process per
directory (a second one refuses to start). Scanners cannot read the outbox or
its key (tool sandbox). Each report carries a stable id the platform uses as
its idempotency key, so a backlog sent after an outage, or a send whose answer
was lost, is stored exactly once. While the sensor runs, its
heartbeat reports the outbox state to the platform (pending results, oldest
age, dead letters, evictions). With the sensor stopped:

```bash
openctemio-sensor -outbox-status            # pending, dead letters with reasons
openctemio-sensor -outbox-requeue-dead      # after fixing the cause; the next start delivers them
# in Docker, against the same volume:
docker run --rm -v openctem-sensor-data:/var/lib/openctem ghcr.io/openctemio/sensor:latest -outbox-status
```

Upgrading: the old `-retry-queue` / `RETRY_QUEUE=true` now turns the outbox on
(also for one-shot runs), and results an older sensor left in its retry-queue
directory (`RETRY_DIR`, default `~/.openctem/retry-queue`) are imported once.

### Rejected key and connection failures

The daemon checks its key with its first heartbeat. When the platform rejects
it (HTTP 401/403: the key is wrong, revoked, expired or regenerated, or the
sensor was deleted), the daemon **stays up**: it stops polling for jobs and
checks again after 30 s, doubling to at most 10 min. It logs one line per
attempt, without `-verbose`:

```
[connection] the platform rejected the API key (HTTP 401, key rda_5d22…): ... Create or regenerate a key under Settings → Sensors, set SENSOR_API_KEY to it and restart the sensor. Not polling for jobs; next check in 30s (attempt 1)
```

It carries on by itself once the key is accepted again, for example after
the sensor is re-activated. A 401 `API key required` means the key never
reached the API: `SENSOR_API_URL` points at the web UI or at a proxy that strips
the `Authorization` header. Network failures are logged at 1, 2, 4, 8, ...
consecutive attempts, along with the recovery.

A one-shot run (`-push`, e.g. in CI) exits with code
**78** (`EX_CONFIG`) when its key is rejected, so the job fails with that
message rather than a generic error.

Restart policy: the daemon no longer exits on a rejected key, so
`restart: unless-stopped` / Kubernetes `restartPolicy: Always` cannot turn
it into a restart loop. Don't treat exit code 78 as transient in wrappers
that retry one-shot runs.

## Setup & health (config report)

On start the daemon runs read-only preflight checks and, when the platform
supports it, sends the results to the platform: open the sensor under
Discovery > Sensors to see its **Setup & health** checklist, each problem
with why it matters and the exact fix (environment variable, Compose or Helm
snippet). The same problems are printed at start (`Warning: ...`) and a
summary line says `Preflight: N passed, M warning(s), K failed`.

What is checked: each tool's binary (missing or installed but failing to
run), whether the state directory survives a recreate, key renewal, the
scanner proxy, OOM protection, the trust store files (`SSL_CERT_FILE`,
`SSL_CERT_DIR`), the local policy and its template keys, unknown or legacy
setting names, unknown keys and unset `${VAR}`s in the `-config` file,
platform commands turned off, and the deprecated `SENSOR_TOOLS` / `-tools`.

What is sent: check ids, codes and typed parameters (a path, a tool or a
setting name), and for every declared setting only whether it is set, where
it came from and whether its value is valid. **Setting values, secrets and
target ranges never leave the host.** Free text is scrubbed of secret values
and URL credentials before it is sent. Nothing the platform sends chooses
what is checked, and no check opens a connection.

## Scanner content updates

A scanner binary is pinned and checksum-verified in the image; the **content**
it scans with changes daily. In daemon mode the sensor manages that content
itself, so scans use a known, verified version instead of whatever a tool
fetches mid-scan:

| Content | Tool | Default source | Verification | Managed |
|---|---|---|---|---|
| `trivy-db` | trivy | `mirror.gcr.io/aquasec/trivy-db:2`, then `ghcr.io/aquasecurity/trivy-db:2` | manifest digest resolved first and downloaded by digest (trivy verifies every blob); `trivy version` must read schema 2; never older than the installed DB unless pinned | always |
| `trivy-java-db` | trivy | trivy's default | trivy reads its metadata | `SENSOR_CONTENT_TRIVY_JAVA_DB=true` (about 800 MB more) |
| `nuclei-templates` | nuclei | the release baked into the image, then the GitHub release (`releases/latest`) | archive sha256 against the release's `_checksums.txt`; safe extraction; at least 1000 templates that nuclei loads; `nuclei -validate` passes for all but `SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS` templates; scans run with `-disable-unsigned-templates` (signature check) and `-disable-update-check` | always |
| `semgrep-rules` | opengrep, semgrep | a local rules path (`SENSOR_CONTENT_SEMGREP_RULES_PATH`, air-gapped); else the rulesets the policy or the operator chose (`https://semgrep.dev/c/<ruleset>`, under the registry licence); else, by default, the signed OpenCTEM rules pack (`github.com/openctemio/sast-rules` releases: the newest, a policy pin or `SENSOR_CONTENT_SAST_RULES_VERSION`) | pack: the archive's cosign keyless signature must verify, offline, for the pack's release workflow at that tag (`checks: sha256, sigstore`); every bundle: YAML check (rules with ids) and the engine loads it | always managed; until the first bundle is installed opengrep and semgrep have no rules and their scans fail (neither ever fetches registry rules itself) |

How it works: every refresh downloads into a staging directory, verifies,
and only then switches the `current` link atomically. A failed download or
check keeps the current version and is reported. A running scan keeps the
version it started with; the previous version is kept for rollback. Checks
run every 6 hours (±10% jitter, hourly while content is missing, stale or
failing) and on demand when the platform sends a `refresh_content` command
("Refresh content" on the Sensors page). The heartbeat reports each tool's
content (`tools[].content`: version, build time, source, digest, last error)
and each result carries the content its scan used (`tool.properties.content`).

The platform's content policy can set the refresh interval, a maximum age,
a pinned version (a trivy DB digest, a nuclei-templates tag) and semgrep
rulesets. **It can never choose where content comes from**: sources are only
this host's settings below.

| Variable | Default | |
|---|---|---|
| `SENSOR_CONTENT` | `on` | `off`: tools fetch their own content, as before |
| `SENSOR_CONTENT_DIR` | `$HOME/.openctem/content` (`/var/lib/openctem/content` in the images) | on the data volume; point it elsewhere to keep the cache on other storage |
| `SENSOR_CONTENT_REFRESH_INTERVAL` | `6h` | 10m..720h; the policy may override |
| `SENSOR_CONTENT_KEEP` | `1` | previous versions kept for rollback (0..10) |
| `SENSOR_CONTENT_TRIVY_DB_REPOSITORY` | see above | comma list, tried in order; registry credentials from `TRIVY_USERNAME`/`TRIVY_PASSWORD` |
| `SENSOR_CONTENT_TRIVY_JAVA_DB` / `_REPOSITORY` | off / trivy default | |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_URL` | GitHub archive | `{version}` / `{bare_version}` placeholders; `https://` or a local file |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_CHECKSUMS_URL` | GitHub release asset | required with a mirror unless `_SHA256` is set |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_LATEST_URL` | GitHub API (only with the default archive URL) | GitHub-shaped JSON or a plain-text tag |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION` / `_SHA256` | none | pin a release / its archive digest |
| `SENSOR_CONTENT_NUCLEI_TEMPLATES_DIR` | none | a local template directory, installed as is |
| `SENSOR_CONTENT_NUCLEI_MIN_TEMPLATES` | `1000` | |
| `SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS` | `10` | templates of a release that may fail `nuclei -validate` before the release is refused; `0`: none |
| `SENSOR_CONTENT_SEMGREP_RULESETS` | none | e.g. `p/default,p/secrets` |
| `SENSOR_CONTENT_SEMGREP_REGISTRY_URL` | `https://semgrep.dev` | a registry mirror |
| `SENSOR_CONTENT_SEMGREP_RULES_PATH` | none | a local rules file or directory |
| `SENSOR_CONTENT_SEMGREP_SKIP_CHECK` | off | skip the semgrep load check (~1 min for `p/default`) |
| `SENSOR_CONTENT_SAST_RULES_VERSION` | the newest release | pin a rules pack release (`vX.Y.Z`); a platform policy pin wins |
| `SENSOR_CONTENT_SAST_RULES_URL` | GitHub releases | a mirror of the pack downloads, a template with `{version}` and `{bare_version}`; the signature is still verified, so a mirror cannot change the rules |

**nuclei templates in detail:**

- The `default` and `nuclei` images bake one nuclei-templates release,
  pinned in the Dockerfiles with its archive SHA-256
  (`NUCLEI_TEMPLATES_VERSION` / `NUCLEI_TEMPLATES_SHA256`) and gated at build
  by `scripts/nuclei-templates-bake.sh`: any template that fails
  `nuclei -validate` with the pinned nuclei and is not in
  `docker/nuclei-templates-allowlist.txt` fails the build, and so does a
  scan run that logs an error or a release whose `.nuclei-ignore` stops
  excluding `dos`, `local`, `fuzz`, `bruteforce` or `txt-service`. The sensor
  adopts the baked set as its first managed version, with its release and
  archive digest, so a fresh sensor scans without downloading anything.
- Each nuclei run over a managed set gets its own nuclei configuration
  directory (`XDG_CONFIG_HOME`, removed after the run) naming that set and
  its release. nuclei confines helper files (payload wordlists, workflow
  subtemplates) to its configured templates directory: without this, every
  template that loads one failed with "access to helper file ... denied"
  (262 templates of v10.4.9, reported as "templates with runtime error").
  The run's `.nuclei-ignore` is the release's own exclusion list plus the
  baseline tags above.
- Template classes the sensor does not enable for its own set (`code`,
  `headless` unless configured, `file`, self-contained) are skipped by
  nuclei, not errors.
- Every finding carries `template_digest` (`sha256:` of the template file
  that matched) and `template_path`; every result carries the release
  (`tool.properties.content`: version and archive digest). A nuclei
  re-verification reports `template_digest`, `templates_version` and
  `templates_digest` in its evidence. The platform compares them to decide
  whether a re-check ran the same template content.

`openctemio-sensor -content-status` prints what is installed;
`-content-refresh` (with `-content-force` to re-download) refreshes now, for
example from cron on a host that runs one-shot scans (one-shot runs use
installed content but never download it).

**Air-gapped hosts:**

- trivy DB: copy the artifact into an internal registry
  (`oras copy mirror.gcr.io/aquasec/trivy-db:2 registry.example.com/aquasec/trivy-db:2`)
  and set `SENSOR_CONTENT_TRIVY_DB_REPOSITORY=registry.example.com/aquasec/trivy-db:2`.
- nuclei templates: put `nuclei-templates-vX.Y.Z.tar.gz` and the release's
  `nuclei-templates-X.Y.Z_checksums.txt` on an internal web server or a
  mounted directory, set `SENSOR_CONTENT_NUCLEI_TEMPLATES_URL=file:///mirror/nuclei-templates-{version}.tar.gz`,
  `SENSOR_CONTENT_NUCLEI_TEMPLATES_CHECKSUMS_URL=file:///mirror/nuclei-templates-{bare_version}_checksums.txt`
  and pin the version (policy or `SENSOR_CONTENT_NUCLEI_TEMPLATES_VERSION`).
- semgrep: `SENSOR_CONTENT_SEMGREP_RULES_PATH=/mirror/semgrep-rules.yaml`.

**Disk:** about 1.5 GB per trivy DB version (two with the default
`SENSOR_CONTENT_KEEP=1`, plus 0.8 GB each with the Java DB), about 150 MB per
nuclei-templates version (the baked one lives in the image), a few MB of semgrep rules.

## Validation (CTEM Stage-4)

Beyond one-shot scanning, the daemon can **re-verify existing findings** so the
platform can confirm-or-downgrade them without a full rescan.

- **`validate`** — advertised **always**. The daemon wraps its command executor
  with a validating executor that runs a non-intrusive TCP-reachability
  safe-check for `validate` commands, regardless of which scanners are enabled
  (`runDaemon` in `main.go`).
- **`validate:nuclei`** — advertised when the vuln-scan (nuclei) image is present
  It re-runs a finding's **own** detection template
  non-destructively and returns `detected` / `not_detected` / `inconclusive` /
  `error` (`internal/executor/validation.go` `RunNucleiValidate`). If the
  template is not installed, the result is `inconclusive` — never a false
  downgrade.
- **`retest:nuclei`**: advertised with `validate:nuclei`. The platform's
  `retest` command lists nuclei findings (the template id of each, and the
  address it is on). The `nuclei-validate` tool checks each address first
  with a TCP connect, then re-runs each finding's own template with the
  re-verification's safety flags. A finding whose template matches again is
  `still_present`. One whose template ran against the reachable address and
  did not match is `fixed`. Anything else is `unverifiable`, including an
  unreachable address and a template that is not installed or is excluded.
  An `unverifiable` item carries a code: `template_not_found`,
  `excluded_by_policy`, `target_unreachable` or `egress_refused`. The
  template runs by its own id with no severity, tag or type filter; only the
  safety exclusions apply.
  The platform closes or reopens findings from these verdicts. The command
  passes the local policy like a scan (`checks.allow` must list `retest` when
  the policy lists check types), and every address passes the validate guard
  (no loopback, link-local or cloud-metadata target).
- **`retest-templates:nuclei`**: advertised with `retest:nuclei`. A retest
  item may carry the organization's own check for a finding, delivered with
  the command (`custom_templates` and `"template": "<id>"` on the item). The
  SDK refuses the command unless the local policy sets
  `allow_custom_templates`, verifies the templates exactly as a scan's (the
  signed job's template digests, else the template manifest signed for this
  sensor and command), runs the custom-template content check (no `code`,
  `javascript`, `flow`, `file`, `headless`, self-contained requests), and
  writes them to a private temporary directory removed after the retest.
  The tool runs exactly that file for the item, with the same tag exclusions,
  rate ceiling, web scope and forwarder as any retest, without nuclei's own
  signature requirement (the trust is the platform signature the SDK
  verified), with `-lna` when the task is not confined to its forwarder and
  a CPU-time cap. It first checks that nuclei loads the file (`-tl`): a file
  that does not load or is excluded by its tags is `unverifiable` ("the check
  could not be loaded: ..."), never `fixed`. Each verdict carries
  `template_digest` = `sha256:` + hex SHA-256 of the file.

## One job, then exit (Kubernetes Job)

`-job <command id>` (or `SENSOR_JOB_ID`) runs the one platform command with
that id and exits, so a launcher can start one sensor pod per job. It always
runs the daemon with platform commands. The sensor:

1. sets up as a daemon does: identity, manifest, tools, local policy, outbox,
   and heartbeats, which keep the job's lease and carry cancels;
2. claims the command by id;
3. runs it with every check a polled command gets (kill switch, served
   command types, expiry, local policy, the platform's tool policy);
4. waits up to 5 minutes for the outbox to deliver the results;
5. exits.

It takes no other work.

| Exit | When |
|---|---|
| `0` | the job ran and its results were delivered. A scan that failed is reported to the platform as failed; retrying the pod would not change it. |
| non-zero | the platform refused the claim (another tenant's command, held by another sensor, no longer pending), the job was not run (it is released for another sensor), or results were not delivered in time |

Mount the data volume (`/var/lib/openctem`, with the outbox) on a persistent
volume. Results that are not delivered before the pod ends are otherwise lost. On SIGTERM the job is
stopped and handed back to the platform.

```yaml
apiVersion: batch/v1
kind: Job
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: sensor
          image: ghcr.io/openctemio/sensor:<version>
          args: ["-job", "$(JOB_ID)"]
          env:
            - {name: JOB_ID, value: "<command id>"}
            - {name: SENSOR_API_URL, value: "https://openctem.example.com"}
          volumeMounts:
            - {name: data, mountPath: /var/lib/openctem}
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: sensor-data}
```

## Tenable.sc connector (moved)

The Tenable.sc connector is no longer part of the sensor: it is its own
image, `ghcr.io/openctemio/connector-tenable`
([openctemio/connector-tenable](https://github.com/openctemio/connector-tenable)),
so the Tenable API keys never share a process or a container with the
scanners. It reads the same config file and key files. A sensor started with
`-tenable-sc-config`, `SENSOR_TENABLE_SC_CONFIG`, a `TENABLE_SC_*` variable or
`/etc/openctem/connectors/tenable-sc.yaml` starts without the connector and
prints a notice.

## Sensor-local policy

The owner of the scanned network sets what this sensor may do, in a
read-only file the platform cannot change (api RFC-040 §5.7):
[`docs/LOCAL_POLICY.md`](LOCAL_POLICY.md), template
[`docs/sensor-policy.example.yaml`](sensor-policy.example.yaml).

```bash
install -o root -g root -m 0644 docs/sensor-policy.example.yaml /etc/openctem/sensor-policy.yaml   # then edit it
docker run … -v /etc/openctem:/etc/openctem:ro ghcr.io/openctemio/sensor:<tag>
touch /etc/openctem/STOP   # kill switch: no job runs until the file is removed
```

Every job is checked after the claim and before any tool runs: its targets
(host names resolved, every address checked), ports, tool, job type, custom
templates and interactsh. A refused job is reported failed with
`refused by local policy: <rule>: <detail>`. Rate and run time are capped.
A malformed policy stops the sensor. Without a policy the sensor works as
before, reports `local_policy: absent` and logs warnings; custom templates
and interactsh are off in any policy unless it turns them on.

### Signed jobs

The platform can sign every command it hands out with a separate job signer
(`openctem-signer`, its own key, outside the API; api RFC-040 §5.6). The
sensor verifies the signature right after the claim, before the local policy,
the command gate and the tool:

- The envelope is Ed25519 over the exact statement bytes, with a pinned key.
- The statement must name this sensor's organization and id, the command's
  id, type and lease epoch, the SHA-256 of the payload as received, the tool
  and targets in it, and the SHA-256 of every custom template it carries.
- It must be issued within the last 2 minutes and not be expired (at most
  1 hour), with a nonce not seen before and a sequence number above the last
  one accepted from that key.
- The last sequence numbers are kept in `<state dir>/job-signing-seq.json`.
  Keep it on the persistent state volume. A corrupt file stops the sensor
  rather than accept old jobs again.

A command that fails the check, or arrives unsigned while signed jobs are
required, is failed with refusal layer `builtin`, rule `job_signature`, and
never runs. The sensor reports `jobs.signed` in its posture: `required`,
`verified_when_present` or `off`.

- **New pairings** with a platform that signs jobs pin its signer keys and
  require signed jobs. A sensor paired by this version always requires them,
  whatever the platform served at pairing: with no key or root pinned it does
  not start until `SENSOR_JOB_SIGNING_ROOT` (shown in the console's install
  snippet) or `SENSOR_JOB_SIGNING_KEYS` is set. Only
  `SENSOR_DANGEROUS_ALLOW_UNSIGNED_JOBS=1` (development) lifts that.
  `SENSOR_REQUIRE_SIGNED_JOBS=false` is a usage error on a sensor that
  pinned keys.
- **Sensors paired earlier** are unchanged. To require signed jobs on one, set
  `SENSOR_JOB_SIGNING_KEYS` to the signer's key id and
  `SENSOR_REQUIRE_SIGNED_JOBS=true`, or pair it again.
- **Key rotation through the root.** When the platform serves a key set
  signed by the installation's offline root, pairing pins that root
  (`identity.json` `job_signing_root`), or the network owner sets
  `SENSOR_JOB_SIGNING_ROOT`. The sensor then accepts job signatures only from
  keys in the current key set (plus `SENSOR_JOB_SIGNING_KEYS`). The key set is
  versioned and expires within 30 days. A lower version is refused, and the
  accepted one is kept in `<state dir>/job-signing-keyset.json`, so a rollback
  is refused across restarts too. A new key set from the platform rotates or
  revokes signer keys without pairing again. With a root pinned and no valid
  key set (none, expired or refused), signed jobs are refused with rule
  `job_keyset`. The sensor warns 7 days before the key set expires, and its
  posture reports `jobs.root`, `jobs.keyset_version` and
  `jobs.keyset_expires_at`.
- **Without a root**, a new signer key is pinned by updating
  `SENSOR_JOB_SIGNING_KEYS` or by pairing again.
- A sensor that requires signed jobs refuses every command of a platform that
  does not sign them.

## Scanner safety model

Scan and validation targets originate from ingested asset data, so every target
passes an SSRF guard before any tool runs (the sdk-go scan-target policy, wired
in `internal/executor/target_security.go`):

- **Hard-blocked, never openable:** cloud metadata / link-local
  (`169.254.0.0/16`, incl. IMDS `169.254.169.254`), loopback (`127.0.0.0/8`,
  `::1`), and carrier-grade NAT (`100.64.0.0/10`), plus multicast/broadcast.
- **Blocked by default, opt-in:** RFC1918 / IPv6 ULA private space
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Set
  `SENSOR_ALLOW_PRIVATE_TARGETS=1` to scan on-prem/internal targets. IMDS,
  loopback, and CGNAT stay blocked regardless.

Targets are checked according to the scanner that receives them. Network
scanners (nuclei, the recon tools, and any scanner the sensor does not know)
get the SSRF guard above. Code scanners (betterleaks, semgrep, trivy fs/config)
take a directory: it must resolve, symlinks followed, inside the scan
workspace (`SENSOR_SCAN_ROOTS`, default the working directory), and never a
sensitive host path (`/etc`, `~/.ssh`, ...). A remote repository URL given to a
code scanner is SSRF-guarded like any network target.

A network target may be a URL (`http`/`https` only), a host, an address, a
range or `host:port` (`203.0.113.7:80`, `[2001:db8::1]:443`, as a port scan
hands targets to the HTTP probe); the host is what is checked. A name that
does not resolve is refused: it cannot be proven safe.

The guard refuses per target (from v0.22.2; up to v0.22.1 the
first refused target fails the whole job). A refused target is removed from the job and
listed in the result (`refused_targets`, rule `target_guard`, with the reason:
`unresolvable`, `denied_by_policy`, `invalid_target`, `wildcard_pattern`), and
its outcome is skipped/refused, so the platform does not hand it out again. The
job runs on the other targets; only a job whose every target is refused fails,
naming each one.

A daemon with platform commands scans only what the server dispatches. It
runs scheduled scans of its own only for targets you configure explicitly
(`-target`, or `targets:` in the config file).

Additional guards on the vuln-scan path:

- **Dangerous-flag blocklist** (sdk-go `core.ValidateExtraArgs`, CWE-77) — rejects
  user-supplied tool flags that redirect output, set a proxy, load an
  attacker-controlled target list / rule / template file, enable the code,
  file, self-contained or headless template types, switch template signature
  checks off, upload results to a third party, or override resolvers /
  interface / source IP. Rate-limit flags are refused too (see below).
- **Nuclei re-verify is detection-only** — the `dos`, `fuzz`, `intrusive`,
  `brute-force` and `default-login` template tags are excluded, the template must have a safe
  matcher, runs are bounded by timeout and rate-limited per asset, and every run
  is logged under its command id (the audit key).

### Reach outcomes

Every job result says which of its targets the sensor reached
(`reach`, `unreached_targets` in the result metadata), so a target the
sensor could not reach is not read as "nothing found". The SDK records the
connections it makes itself; the tools add what their output shows:

| Tool | Reached | Not reached |
|---|---|---|
| httpx | every URL that answered | `-probe` failures: no route, timeout, refused, no address for the name |
| naabu | every open port | a run that failed on the target (a name that does not resolve) |
| nuclei | - | hosts nuclei skipped as unresponsive (timeout, or the error nuclei names) |
| dnsx | - | names with no answer in this sensor's DNS view (address queries only) |

A host with no open port is not counted either way. Only the job's own
targets are recorded; an address is kept only inside an address or range
target. A scan with an unreached target completes as partial coverage.

### Reach probe

On the platform's request the sensor tests whether it reaches a job's
targets: one TCP connect per address and port (443, 80, 22) until one
answers, no payload, no ICMP. The outcome is the job's reach summary; the
probe reports no findings.

- It dials only through the [local policy](#sensor-local-policy): the job's
  admitted targets, `targets.allow`/`deny`, `ports.allow` and the built-in
  deny list, by address, never by name. A sensor without a policy object, a
  job limited to tier T0, a web scope or port limits is refused.
- At most 10 connects per second (lower when the job or `rate.max_rps` asks),
  one per address at a time, 256 addresses per job, 2 s per connect.
- A policy with `tools.allow` must list `reach-probe` to allow it.

See [Network requirements](https://docs.openctem.io/sensors/network/#what-targets-need).

### Nuclei template trust and rate limits

The sensor's own nuclei templates (the managed `nuclei-templates` release,
or the templates baked into the image) always run with
`-disable-unsigned-templates`: nuclei skips any template whose
ProjectDiscovery signature is missing or does not match. The code protocol
is never enabled: the sensor never passes `-code`, `-file`, `-esc` or
`-dast`, passes `-headless` only when configured in code, and refuses all of
them (and `-dut=false`) in extra args.

**Non-intrusive only** (api RFC-036, tier T1). Every nuclei run, of the
sensor's own templates or of custom templates, gets
`-etags intrusive,default-login,dos,fuzz,fuzzing,bruteforce,brute-force,local,txt-service`
on the command line (with or without managed templates), plus any tags the
operator or the scan excludes. A scan whose `tags` setting names one of
these classes fails with the reason instead of running; a scan's
`exclude_tags` only adds to the list; and `-itags` / `-include-tags`, the
only nuclei flags that re-admit an excluded template, are refused in extra
args (nuclei v3.11.1 drops an `-etags` template however it was selected:
directory, explicit `-t` file, `-id` or `-tags`). Re-verifications exclude
`default-login` as well. There is no intrusive mode. Planned: an intrusive
mode that needs an approved grant on the command, within a ceiling the
network owner sets (RFC-036 T2).

Custom templates (uploaded by a tenant admin on the platform) are not signed
by ProjectDiscovery, so they are trusted another way.

**With signed jobs** (the sensor verifies the platform's
[signed jobs](#signed-jobs)), the job statement lists the SHA-256 of every
custom template in the payload. The platform's job signer lists a template only
when its digest was approved in the signer's scope ledger (api RFC-040 P2).
The sensor compares the decoded templates with the verified list before writing
them, and needs no `SENSOR_TEMPLATE_SIGNING_KEYS`. Steps 1, 3 and 4 below, and
the local `allow_custom_templates` gate, still apply.

**Without signed jobs**, the per-tenant template manifest is the fallback,
planned for removal:

1. The platform refuses, at upload, templates that use the `code`,
   `javascript`, `headless` or `file` protocol or are self-contained.
2. When it hands a command to a sensor, the platform validates every
   template again and signs one manifest of the set (tenant, this sensor,
   this command, issue and expiry time, and the id, name, type and SHA-256
   of each template) in a DSSE envelope with an Ed25519 key derived for the
   tenant. The sensor (sdk-go) verifies the envelope against
   `SENSOR_TEMPLATE_SIGNING_KEYS` before parsing it, then refuses a manifest
   for another command (or another sensor, when `SENSOR_ID` is set), an
   expired one, and any template changed, added, held back or reordered.
   Without a pinned key, scans with custom templates fail.
3. The sensor checks the templates itself again (`core.CheckCustomTemplate`
   in the SDK before they are written, `CheckCustomTemplates` before the
   run): `code`, `javascript`, `flow`, `file`, `headless`, self-contained
   requests, `workflows`, payload files and multi-document files are
   refused.
4. The job's **rule sources** decide what runs (api RFC-118):
   - `both` (the default): **one** nuclei run with the sensor's own
     templates and the custom templates. With `-disable-unsigned-templates`
     (the default), nuclei gets copies of the custom templates signed with
     a key made for this run alone, and that key's certificate in
     `NUCLEI_USER_CERTIFICATE`; the private key never leaves the sensor and
     is discarded when the run ends, so nuclei loads exactly the templates
     the sensor checked, and the own set still needs its ProjectDiscovery
     signature. The run gets the custom templates' limits: a CPU-time cap
     and, without network confinement, `-lna`;
   - `tenant`: the custom templates alone, with
     `-exclude-type code,file,headless,javascript`, never `-headless`;
   - `platform`: the sensor's own templates; a job that carries custom
     templates is refused.

   Results of custom templates carry `tenant:`-prefixed template ids and
   `rule-source: tenant`, and the digest of the template as received.
   The sensor reports the `rule.sources@1` capability; the platform sends
   tenant-only jobs only to sensors that do.

The same rule sources apply to betterleaks (`both`: the organization's
rules extend the sensor's config, else the default rules, and may not carry
a global allowlist or `[extend]` settings that would disable them;
`tenant`: the organization's rules alone; an `[extend]` path or url is
always refused) and to opengrep and semgrep (`both`: the organization's
rules and the platform pack in one run; `tenant`: only the organization's).
Their organization rule ids are reported with the `tenant:` prefix too.

Pin the key once per sensor:

```bash
# On the platform, as a tenant admin:
curl -H "Authorization: Bearer $TOKEN" https://openctem.example.com/api/v1/scanner-templates/signing-key
# -> {"algorithm":"ed25519","key_id":"…","public_key":"<base64>"}
docker run … -e SENSOR_TEMPLATE_SIGNING_KEYS=<base64> ghcr.io/openctemio/sensor:<tag>
```

To roll the platform key, pin the new key next to the old one
(comma-separated), rotate on the platform, then drop the old one.

**Rate limits.** nuclei always gets `-rate-limit`, `-c` and `-bs`. A scan
command may ask for lower values (config `rate_limit`, `concurrency`,
`bulk_size`); the sensor uses them up to the ceilings
`SENSOR_NUCLEI_MAX_RATE_LIMIT` / `_CONCURRENCY` / `_BULK_SIZE` (default
150 / 25 / 25, nuclei's own defaults) and never above. A value outside
1..1000000 stops the sensor at start. Rate-limit flags in extra args
(`-rate-limit`, `-bs`, `-c`, `-per-host-rate-limit`, ...) are refused.
Re-verification (`validate:nuclei`) runs at 20 requests per second, or the
ceiling when it is lower.

**Tool performance options.** Each tool's manifest declares how hard it may
work; the platform shows them on the sensor's **Tool settings** tab (Discovery >
Sensors > the sensor; **Show effective values** lists each value with its
source and native flag) and sends the sensor's settings with every signed job. Rate, concurrency, timeout
and retries are the common options: only the sensor's settings may raise rate, concurrency or retries above the default, while a
scan or the job's decision may only lower them, and a scan asking for more is
refused. The sensor's local policy (`rate.max_rps`) and the operator's
ceilings cap the result last. A *sensor* option can only be set in the
sensor's settings.

| tool | option (native flag) | default | who sets it |
|---|---|---|---|
| nuclei | `rate_limit` (`-rate-limit`), `concurrency` (`-c`), `timeout` (`-timeout`), `retries` (`-retries`) | 150, 25, 10 s, 1 | common |
| nuclei | `bulk_size` (`-bs`) | 25 | sensor |
| nuclei | `max_host_errors` (`-mhe`), `scan_strategy` (`-ss`) | 30, auto | scan |
| naabu | `rate` (`-rate`), `retries` (`-retries`) | sensor's rate, naabu's | common |
| httpx | `rate_limit` (`-rl`), `threads` (`-threads`), `timeout` (`-timeout`), `retries` (`-retries`) | 150, 50, 10 s, 2 | common |
| dnsx | `rate_limit` (`-rl`), `threads` (`-t`), `timeout` (`-timeout`), `retries` (`-retry`, attempts = retries + 1) | none, 100, 3 s, 1 | common |
| dnsx-enum (T1, subdomain brute force; needs the job's label list, never a built-in one) | `rate_limit` (`-rl`, a scan only lowers it; the sensor settings raise it to 500 at most), `threads` (`-t`, at most 200), `timeout`, `retries`, `max_queries` (first N labels) | 50 per second, 50, 3 s, 1, whole list | common |
| subfinder | `rate_limit` (`-rl`), `timeout` (`-timeout`, per source) | none, 30 s | common |
| katana | `rate_limit` (`-rl`), `concurrency` (`-c`), `timeout` (`-timeout`), `retries` (`-retry`) | 150, 10, 10 s, 1 | common |
| trivy | `parallel` (`--parallel`, 0 = one per CPU) | 5 | sensor |

trivy always gets `--timeout` equal to the run's bound (its own default of
five minutes ended large scans early), `--disable-telemetry` and
`--skip-version-check`, and `--skip-check-update` when the sensor manages
its database.

## Upgrading from the agent release

The binary, images and settings were renamed from *agent* to *sensor*
([RFC-023 §9.5](https://github.com/openctemio/openctem/blob/main/api/docs/rfcs/RFC-023-scan-zones-and-scanners.md)).
A sensor upgraded in place keeps working with its existing configuration:

| Before | After | On upgrade |
|---|---|---|
| binary `agent` | `openctemio-sensor` | — |
| image `ghcr.io/openctemio/agent:<tag>` | `ghcr.io/openctemio/sensor:<tag>` | old tags stay pullable and frozen (never updated, never deleted) |
| `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` | `SENSOR_ID`, `SENSOR_NAME`, `SENSOR_ALLOW_PRIVATE_TARGETS` | refused at startup, naming the new name: rename them first |
| `-agent-id` | `-sensor-id` | old flag applied, startup warning |
| config `agent:` block, `server.agent_id` | `sensor:`, `server.sensor_id` | old keys applied, startup warning |
| `~/.openctem/agent-credentials.json` | `~/.openctem/sensor-credentials.json` | moved on first start (written 0600 and read back before the old file is removed); same identity and key, no re-registration. If the file cannot be moved (read-only mount) it is used in place. `-credentials <path>` is used as is. |
| `API_URL`, `API_KEY`, `REGION`, `PLATFORM_KEY_AUTORENEW` | `SENSOR_API_URL`, `SENSOR_API_KEY`, `SENSOR_REGION`, `SENSOR_KEY_AUTORENEW` | refused at startup, naming the new name: rename them first |

The sensor refuses to start only when an old and a new name are both set to
**different** values; the error names both (never the values). The sensor
speaks protocol v2 only, so it needs an OpenCTEM API from 2026-10-02 on (see
[Results delivery and the outbox](#results-delivery-and-the-outbox)).

## Upgrading: gitleaks → Betterleaks

[Betterleaks](https://github.com/betterleaks/betterleaks) replaces gitleaks as
the secret scanner. It is gitleaks' successor by its original author (MIT): v1
keeps gitleaks' CLI flags, config format and JSON report, and adds BPE-token
filtering, Expr rule filters and validation, recursive decoding and scanning
inside archives (on by default).

- The image is `ghcr.io/openctemio/sensor:<version>-betterleaks`. No
  `-gitleaks` image is published from this release on; existing `-gitleaks`
  tags stay pullable and frozen.
- The scanner is `betterleaks` (`-tool betterleaks`, the local policy's
  `tools.allow`, `scanners: - name: betterleaks`). `gitleaks` in an existing command line,
  config or CI template still works: it runs betterleaks and prints a note.
  A platform that has not migrated its scan configs and still dispatches
  `gitleaks` scans is handled the same way.
- `.gitleaks.toml` custom rules keep working (betterleaks reads them;
  `.betterleaks.toml` is the new name).
- Findings keep their identity: a secret both tools report has the same
  fingerprint, so existing findings are updated, not duplicated. Rule sets
  differ, for example betterleaks reports an AWS access key ID only together
  with its secret key, so a few gitleaks-only findings are auto-resolved by
  the first full betterleaks scan, and archives produce new ones.
- Upgrade every sensor that scans a repository together: a gitleaks sensor
  and a betterleaks sensor on the same repository resolve and reopen each
  other's rule-set differences.
- The platform maps reports from older sensors (`tool: gitleaks`) to
  `betterleaks` at ingest and migrates scan configs and existing findings
  (API migration 000241).

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `x509: certificate signed by unknown authority` | The API uses a private CA | [Trust the CA](#https-with-a-private-ca) |
| `http 421 ... WRONG_ENDPOINT` or `API key required` | `SENSOR_API_URL` points at the web UI or at a proxy that strips `Authorization` | Point `SENSOR_API_URL` at the API |
| `the platform does not serve sensor protocol v2` | The OpenCTEM API predates protocol v2 | Upgrade the platform |
| `-platform mode has been removed` | A command line that still passes `-platform` (images up to v0.3.0 used it as their default command) | Drop it: the daemon is the default mode |
| `SENSOR_ALLOW_PRIVATE_TARGETS="true" is not recognized` | Only `1` or `0` is accepted | Set `1` |
| `[connection] the platform rejected the API key` | The key is wrong, revoked, expired or regenerated, or the sensor was deleted | See [Rejected key and connection failures](#rejected-key-and-connection-failures) |
| `paused by platform` | The sensor is deactivated: it keeps heartbeating and takes no jobs | Reactivate it under Discovery > Sensors |
| `refused by local policy: ...` | The sensor-local policy refuses the job | See [docs/LOCAL_POLICY.md](LOCAL_POLICY.md) |

- **Connection refused**: check `SENSOR_API_URL` (`curl $SENSOR_API_URL/health`) and the
  firewall. From a container on Docker Desktop (macOS, Windows), reach a
  platform on the host as `http://host.docker.internal:8080`.
- **Tool not found**: `openctemio-sensor -check-tools` names the missing
  binaries and how to install them; `-install-tools` installs them.
- **No findings**: run the scanner with `-verbose` and check that it is
  installed (`-list-tools`). One-shot runs push a report only when it has
  findings.
- Every start prints the preflight problems and the platform shows them under
  the sensor's **Setup & health** (see below).

