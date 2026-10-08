# Tenable.sc connector

The sensor can pull hosts, vulnerabilities and plugin metadata from a
Tenable Security Center (Tenable.sc) inside your network and send them to
OpenCTEM. The sensor is the only component that talks to Tenable.sc. The
Tenable API keys stay on the sensor: OpenCTEM never receives, stores or
forwards them, and needs no route into your network.

Design: api `docs/rfcs/RFC-047-tenable-sc-sensor-connector.md` in
`openctemio/openctem`.

## How it works

1. In OpenCTEM, a Tenable.sc integration names this sensor and an
   **instance name** (for example `sc-prod`). That name is the only thing the
   platform knows about your Tenable.sc.
2. On a schedule, or when someone clicks "Sync now", the platform queues a
   `connector_sync` command for this sensor.
3. The sensor checks the command against the sensor-local policy
   (`checks.allow` must allow `connector_sync`, and `tools.allow` must allow
   `tenable_sc` if those lists are set) and against this connector's own
   allow-list. It then reads Tenable.sc and pushes CTIS reports bound to the
   command.

The platform can ask for an incremental or full sync, a minimum severity and
a subset of repositories. It cannot send a URL, a header, a query or a
filter, and it can only narrow the repositories you allowed.

## Configuration

The config file is written by the network owner and mounted read-only:

```yaml
# /etc/openctem/connectors/tenable-sc.yaml  (root-owned, 0640, read-only mount)
apiVersion: openctem.io/connector-tenable-sc/v1
instances:
  - name: sc-prod                       # what the OpenCTEM integration names
    url: https://sc.example.com          # https only
    ca_file: /etc/openctem/tenable-ca.pem          # optional; replaces the system roots
    pin_spki_sha256: ["kV2x...="]                   # optional; base64 SHA-256 of the SubjectPublicKeyInfo
    access_key_file: /run/secrets/tenable_sc_access_key
    secret_key_file: /run/secrets/tenable_sc_secret_key
    allow:
      operations: [sync]                # add "scan" to let OpenCTEM launch scans
      repositories: [5, 7]              # required: nothing is read without it
      # Only with operations: [sync, scan]:
      scan_policies: [1000003]          # policies a launched scan may use (required for scan)
      scan_repositories: [5]            # repositories its results may go to (required for scan)
      scan_zones: [2]                   # optional; 0 is Tenable's default zone
      max_targets_per_scan: 512         # addresses per scan, CIDRs counted by size
      max_scan_seconds: 28800           # longest scan the platform may ask for
    limits:
      page_size: 1000                   # 50..5000
      max_records: 1000000              # per sync, all queries
      max_response_bytes: 67108864      # per HTTP response (1 MiB..512 MiB)
      requests_per_second: 5            # at most 50
```

Location: `-tenable-sc-config`, else `SENSOR_TENABLE_SC_CONFIG`, else
`/etc/openctem/connectors/tenable-sc.yaml` when it exists. Without a config
the connector is off and the sensor does not report the `tenable_sc` tool.

For a single instance, environment variables work too (instance name
`default`):

| Variable | Meaning |
|---|---|
| `TENABLE_SC_URL` | `https://` base URL |
| `TENABLE_SC_ACCESS_KEY_FILE`, `TENABLE_SC_SECRET_KEY_FILE` | key files (recommended) |
| `TENABLE_SC_ACCESS_KEY`, `TENABLE_SC_SECRET_KEY` | raw keys (accepted with a warning: environment values leak more easily) |
| `TENABLE_SC_CA_FILE` | CA file |
| `TENABLE_SC_REPOSITORIES` | allowed repository ids, comma-separated (required) |
| `TENABLE_SC_OPERATIONS` | allowed operations (default `sync`) |

### Fail closed

The sensor refuses to start when the config has an unknown key, a non-https
URL, a missing or world-writable config or key file, a key with characters an
API key cannot have, a duplicate instance name, no repositories, or both a
file and `TENABLE_SC_URL`. There is no option to skip TLS verification.

## TLS and network

- TLS 1.2 or later, with the system roots or your `ca_file`, plus optional
  SPKI pins. The host name is always verified.
- Redirects are refused, so the key header never goes to another host.
- Private addresses are allowed (Tenable.sc is internal). Loopback,
  link-local, cloud metadata, multicast and unspecified addresses are refused.
- Requests are rate limited. 429, 502, 503 and 504 are retried with backoff
  (honouring `Retry-After`, at most 60 s, 5 attempts). 401 and 403 are never
  retried.

## Scan launch (connector_scan)

When an instance allows `scan`, the sensor runs `connector_scan` commands
from OpenCTEM scan runs (OpenCTEM owns the schedule; nothing is scheduled in
Tenable.sc). Before any Tenable.sc call the sensor checks, and refuses the
whole job on any violation:

- the policy, repository and zone are in `scan_policies`,
  `scan_repositories` and `scan_zones`;
- every target is one IP address, an IPv4 range of /16 or narrower, an IPv6
  range of /120 or narrower, or a host name (no URLs, ports or lists), and
  the targets cover at most `max_targets_per_scan` addresses;
- no target is loopback, link-local, cloud metadata, multicast or reserved;
- every target passes the sensor-local policy (`-local-policy`), again here
  after the job admission.

It then creates one scan named `openctem-<command id>` (the targets as its IP
list, `timeoutAction: import`), launches it, polls the scan result every 30
seconds, reads the result's findings and hosts and pushes them bound to the
command, and deletes the scan definition it created (the results stay). It
never edits, launches or deletes any other scan. The reports say coverage
`full` only when the scan completed and its import finished; anything else
(error, partial, stopped, no results, past `max_scan_seconds` plus 30 minutes
for the import, when it is stopped) is `partial`, which never closes a
finding by absence. A cancelled command stops the scan.

`connector_sync` also reports a catalog of the repositories, scan
repositories, policies and zones you allowed (ids and names), so OpenCTEM
can offer them; objects outside your allow-lists are never listed.

## A least-privilege Tenable.sc user

Create a dedicated Tenable.sc user for OpenCTEM. Give it a role that can only
view vulnerability data, and only for the repositories you list in
`allow.repositories`. Do not give it administrator rights. For scan launch,
add only the right to create scans, share with it only the policies in
`scan_policies`, and give it the repositories in `scan_repositories` and the
zones in `scan_zones`; without scan launch, give it no scan rights. Generate its API keys (Tenable.sc 5.13 or later, with API key
authentication enabled under System Configuration) and store them in the key
files, owned by root and readable only by the sensor's user.

## What is sent to OpenCTEM

- Hosts as assets (DNS name, else IP), with IP, NetBIOS name, OS, MAC
  addresses, Tenable host UUID, repository, ACR and AES.
- Vulnerabilities as findings: plugin id and name, severity, all CVEs,
  CVSS (v3, else v2, with the version; v4 as a property), VPR, EPSS,
  exploit availability and frameworks, plugin family and type, publication
  and patch dates, first and last seen, port and protocol, plugin output
  (at most 64 KiB), accept-risk and recast-risk flags, and the open or
  mitigated state. Mitigated rows carry the status `resolved`; the platform
  decides what to do with them.
- On completion: counts, the Tenable.sc version and the licensed and active
  IP counts. Never the URL or the keys.

Every Tenable.sc response is treated as untrusted: size caps, per-field
caps, control and bidi characters removed, only `http`/`https` references,
scores and dates outside their ranges dropped. A malformed response or a
query with more records than `max_records` fails the sync before anything
from that query is pushed.
