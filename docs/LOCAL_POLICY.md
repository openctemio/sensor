# Sensor-local policy

The sensor-local policy is a read-only file that the owner of the scanned
network writes when the sensor is installed. The sensor refuses every job
outside it, even one the platform sent, and even once jobs are signed. A
compromised platform, API or database therefore cannot point the sensor at
networks, ports or tools the owner did not allow. This is the "the host owner
has the last word" principle of
[api RFC-040](https://github.com/openctemio/openctem/blob/main/api/docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md)
§5.7 (owner decisions Q3 (a) and Q4 (a)).

The platform cannot change the policy. The sensor reports only its state,
digest and a summary (counts, tools, switches; never the ranges) on the
heartbeat and the manifest, and only to a platform that announces the
`local_policy` feature.

Template: [`sensor-policy.example.yaml`](sensor-policy.example.yaml).

## Where the sensor reads it

| Setting | Effect |
|---|---|
| `-local-policy <file>` or `SENSOR_LOCAL_POLICY=<file>` | the policy; the file must exist |
| neither | `/etc/openctem/sensor-policy.yaml` when it exists |
| no file, `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` | a shorthand policy: `targets.allow` and `ports.allow` only, everything else at its policy default (templates and callbacks off). Setting a shorthand together with a file is an error |
| no file, no shorthand | **no policy**: see below |
| `SENSOR_KILL_SWITCH_FILE=<absolute path>` | a kill switch file, with or without a policy |

The sensor reads the policy once at start; restart it after a change. At start
it logs `Local policy: enforced from file … (sha256:…): targets allow N, deny
N, private …, ports …, tools …, custom templates …, interactsh …`.

**It fails closed.** The sensor does not start (exit code 2) when the file:

- has an unknown key or a key in the wrong place;
- has a malformed CIDR, IP, host name, port or tool name, or a CIDR with host
  bits set (`10.20.1.0/16`);
- holds more than one YAML document, or is empty;
- is writable by every user;
- lists a private range in `targets.allow` without `allow_private: true`, or
  an always-blocked range (loopback, cloud metadata);
- was configured with `-local-policy` or `SENSOR_LOCAL_POLICY` but does not
  exist.

## The keys

`apiVersion: openctem.io/sensor-policy/v1` is required. An absent section
restricts nothing; an absent switch is off; an empty list (`[]`) allows
nothing.

| Key | Meaning |
|---|---|
| `targets.allow` | CIDRs, IPs, host names, `*.domain` (every name below the domain). A host name passes when it matches a domain entry, or when every address it resolves to lies in a range entry. A range target must lie inside one range entry. |
| `targets.deny` | the same forms; never scanned, even when `allow` matches. Every address a name resolves to is checked, so a name that resolves into a denied range is refused (DNS rebinding). |
| `targets.allow_private` | RFC 1918 / IPv6 ULA ranges may be scanned. `SENSOR_ALLOW_PRIVATE_TARGETS=1` is needed as well. The built-in deny list (loopback, link-local and metadata, CGNAT, multicast, reserved) always applies. |
| `ports.allow` | `"80,443,8000-8999"`: ports a job names (`host:port`, or a URL's port; `http` is 80, `https` 443), and every port of a job's `ports` setting (a port scan's list; a value the sensor cannot read, such as `top-1000`, is refused). |
| `tools.allow` | tools that may run; the others are neither run nor reported, so the platform does not route jobs for them here. |
| `checks.allow` | job types: `scan`, `validate`, `collect`, `refresh_content`. `health_check` is always allowed. |
| `allow_custom_templates` | platform-supplied custom templates (they must also carry the platform's signature, `SENSOR_TEMPLATE_SIGNING_KEYS`). |
| `allow_interactsh` | out-of-band callbacks (nuclei interactsh). |
| `rate.max_rps` | requests per second; no scan runs above it, whatever the job asks for. |
| `rate.max_job_seconds` | longest run of a job. Every job is capped at 24h anyway. |
| `kill_switch` | `true` stops every job until the policy changes. |
| `kill_switch_file` | while this file exists the sensor stops every job. |

## What a refusal looks like

The sensor checks a job after claiming it and before any tool sees it. A
single violation refuses the whole job; nothing runs partially. The job is
reported **failed** with a reason the platform shows, for example:

```
refused by local policy: targets.deny: 10.20.5.9 (resolved from db.corp.example.com) is in 10.20.5.0/24
refused by local policy: targets.allow: 192.0.2.1 is not in an allowed range
refused by local policy: ports.allow: port 22 is not in 80,443,8000-8999
refused by local policy: tools.allow: naabu is not allowed on this sensor
refused by local policy: allow_interactsh: the job asks for out-of-band callbacks (interactsh); this sensor's policy does not allow them
refused by local policy: kill_switch: kill switch file /etc/openctem/STOP is present
```

The rule names the key to change if the job should run. The platform's own
settings (its tool policy, a scan's `allow_interactsh`, `rate_limit`,
`timeout_seconds`) can narrow what the policy allows, never widen it.

## The kill switch

```bash
touch /etc/openctem/STOP     # stop: nothing is claimed, running jobs are stopped
rm /etc/openctem/STOP        # resume
```

The sensor checks the file every 2 seconds. While the file exists, the sensor
keeps sending heartbeats with the message `paused by local policy`, so the
platform shows the sensor as paused rather than offline. Jobs that were
running are reported failed with `kill_switch`. If the file cannot be checked
(for example, permission denied), the sensor treats the switch as on.

The file's directory must be visible inside the container. Mount the
directory, not the file: a file mount cannot appear later.

## Without a policy

A sensor without a policy works as it did before (owner decision Q3 (a)):

- only the built-in deny list and `SENSOR_ALLOW_PRIVATE_TARGETS` limit targets;
- custom templates (signed only) and interactsh stay allowed when a job asks
  (owner decision Q4 (a): existing installs keep their behavior), with a
  warning in the log for each such job;
- it logs warnings at start and reports `local_policy: {"state": "absent"}`, so
  the platform can flag it.

New installs should always ship a policy. In a policy, custom templates and
interactsh are **off** unless the policy turns them on.

## Install dialog

This section is for the platform's sensor install dialog (api/web follow-up),
and for anyone writing the policy by hand.

1. Offer the policy as a step of the install command, prefilled from what the
   platform knows (a zone's ranges, the tenant's verified domains). The
   **network owner** edits and approves it. The platform must never install or
   change it afterwards.
2. Defaults for a new install: `allow_custom_templates: false`,
   `allow_interactsh: false`, `kill_switch_file: /etc/openctem/STOP`, and
   `allow_private` only for an on-prem zone (with
   `SENSOR_ALLOW_PRIVATE_TARGETS=1`).
3. Render the mount read-only for each target:

   Docker:

   ```bash
   install -o root -g root -m 0644 sensor-policy.yaml /etc/openctem/sensor-policy.yaml
   docker run -d --name openctem-sensor \
     -v /etc/openctem:/etc/openctem:ro \
     -e API_URL=… -e API_KEY=… \
     ghcr.io/openctemio/sensor:<tag> -daemon -enable-commands
   ```

   Compose:

   ```yaml
   services:
     sensor:
       image: ghcr.io/openctemio/sensor:<tag>
       command: ["-daemon", "-enable-commands"]
       volumes:
         - /etc/openctem:/etc/openctem:ro
   ```

   Kubernetes (the platform has no write access to this ConfigMap's namespace
   or RBAC):

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata: { name: openctem-sensor-policy }
   data:
     sensor-policy.yaml: |
       apiVersion: openctem.io/sensor-policy/v1
       …
   ---
   # in the sensor Deployment's pod spec
   volumes:
     - name: policy
       configMap: { name: openctem-sensor-policy, defaultMode: 0444 }
   containers:
     - name: sensor
       volumeMounts:
         - { name: policy, mountPath: /etc/openctem, readOnly: true }
   ```

   To stop jobs on Kubernetes, set `kill_switch: true` in the ConfigMap and
   restart the pod, or name a `kill_switch_file` on a writable volume that
   the host owner controls.
4. After installation, the sensor page shows the policy state (`enforced`,
   `absent`, or paused by the kill switch), the digest and the summary.

## Limits of this version

- The policy checks the targets a job names and every connection made through
  the sensor's guarded dialer (the safe-check, and the RFC-034 forwarder once
  it ships), and a job's `ports` setting. A tool's own default port set
  (naabu without a `ports` setting) and raw sockets are limited by the
  targets but not by `ports.allow`.
  Pair the policy with a host firewall rendered from it (RFC-040 §5.10).
- A scanner resolves a host name again when it runs. The admission check
  refuses a name that resolves into a denied range, but a name that changes
  its answer between the check and the scan is caught only by the guarded
  dialer and the host firewall.
- An unresolvable dotless name (an image reference such as `alpine`) reaches
  no target network and is not checked against `targets.allow`.
