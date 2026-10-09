# Sensor-local policy

The sensor-local policy is a read-only file that the owner of the scanned
network writes when the sensor is installed. The sensor refuses every job
outside it, even one the platform sent, and even once jobs are signed. A
compromised platform, API or database therefore cannot point the sensor at
networks, ports or tools the owner did not allow. This is the "the host owner
has the last word" principle of
[api RFC-040](https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md)
§5.7.

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

The sensor reads the policy at start and again on **SIGHUP**
(`kill -HUP <pid>`, `docker kill -s HUP <container>`). A reloaded file that
loads replaces the policy for new jobs; a running job keeps the policy it was
admitted under. **A reloaded file that does not load stops every job** (the
kill switch engages, the log and the platform show `local policy reload
failed (…)`) until a later SIGHUP loads a valid file: the sensor never keeps
running on the previous policy, which may be the looser one you just tried to
tighten. At start it logs `Local policy: enforced from file … (sha256:…): targets allow N, deny
N, private …, ports …, tools …, custom templates …, interactsh …`.

**It fails closed.** The sensor does not start (exit code 2) when the file:

- has an unknown key or a key in the wrong place;
- has a malformed CIDR, IP, host name, port or tool name, or a CIDR with host
  bits set (`198.51.100.0/16`);
- holds more than one YAML document, or is empty;
- is writable by every user;
- lists a private range in `targets.allow` without `allow_private: true`, or
  an always-blocked range (loopback, cloud metadata);
- was configured with `-local-policy` or `SENSOR_LOCAL_POLICY` but does not
  exist.

## The keys

`apiVersion` is required: `openctem.io/sensor-policy/v1` or
`openctem.io/sensor-policy/v2`. An absent section restricts nothing; an absent
switch is off; an empty list (`[]`) allows nothing.

**Schema versions.** v1 is frozen: it never gains a key, because a sensor
refuses a key it does not know, so a new v1 key would stop every older
sensor. New keys go into a new version. v2 is every v1 key below, plus
`managed`. A file is checked strictly against the keys of the version it
declares: a v1 file with a v2 key is refused. Sensors report the versions
they read (`local_policy.schemas`), and v0.9.x sensors read only v1: write v1
for them. `openctemio-sensor policy validate` tells you before you install.

| Key (v2 only) | Meaning |
|---|---|
| `managed.accept` | `false`: this sensor ignores any policy the platform manages for it (narrowing documents the platform will send; they can never widen this file). The platform shows the sensor as locked by its owner. Default `true`. |

| Key | Meaning |
|---|---|
| `targets.allow` | CIDRs, IPs, host names, `*.domain` (the domain itself and every name below it, at any depth, as the platform reads a scope pattern; deny the domain exactly to keep it out). Names compare case-insensitively, without a trailing dot, in IDNA ASCII form. A host name passes when it matches a domain entry, or when every address it resolves to lies in a range entry. A range target must lie inside one range entry. |
| `targets.deny` | the same forms (`*.domain` denies the domain too); never scanned, even when `allow` matches. Every address a name resolves to is checked, so a name that resolves into a denied range is refused (DNS rebinding). |
| `targets.allow_private` | RFC 1918 / IPv6 ULA ranges may be scanned. `SENSOR_ALLOW_PRIVATE_TARGETS=1` is needed as well. The built-in deny list (loopback, link-local and metadata, CGNAT, multicast, reserved) always applies. |
| `ports.allow` | `"80,443,8000-8999"`: ports a job names (`host:port`, or a URL's port; `http` is 80, `https` 443), and every port of a job's `ports` setting (a port scan's list; a value the sensor cannot read, such as `top-1000`, is refused). |
| `tools.allow` | tools that may run; the others are neither run nor reported, so the platform does not route jobs for them here. |
| `checks.allow` | job types: `scan`, `validate`, `retest`, `collect`, `refresh_content`. `health_check` is always allowed. |
| `allow_custom_templates` | platform-supplied custom templates (they must also carry the platform's signature, `SENSOR_TEMPLATE_SIGNING_KEYS`). |
| `allow_interactsh` | out-of-band callbacks (nuclei interactsh). |
| `rate.max_rps` | requests per second; no scan runs above it, whatever the job asks for. |
| `rate.max_job_seconds` | longest run of a job. Every job is capped at 24h anyway. |
| `kill_switch` | `true` stops every job until the policy changes. |
| `kill_switch_file` | while this file exists the sensor stops every job. |

## Commands

The sensor binary checks and installs policies. They read local files only
and never contact the platform.

```bash
openctemio-sensor policy validate [file]   # parse it as the sensor does (exit 1 if invalid)
openctemio-sensor policy digest   [file]   # the sha256 the sensor reports
openctemio-sensor policy explain  [file] -target app.example.com:8443 -tool nuclei
                                           # admitted, or the rule that refuses it
sudo openctemio-sensor policy install sensor-policy.yaml --expect-sha256 <hash shown with the file> \
     [-dest /etc/openctem/sensor-policy.yaml] [-dry-run] [-pid <sensor pid>]
```

`install` refuses a file whose sha256 is not the one given (install only the
bytes you reviewed), a policy this sensor cannot read, a destination that is a
symlink or not a regular file, and a destination directory anyone can write.
It prints the change (before / after), writes the file atomically (0644,
temporary file, fsync, rename) and, with `-pid`, sends the sensor SIGHUP. The
hash is yours to check, not a key the platform holds: the platform never
writes this file.

## What a refusal looks like

The sensor checks a job after claiming it and before any tool sees it.

**Per target.** A scan job's target that the policy refuses, or that the
sensor cannot check, is removed from the job before any tool sees it. The job
runs on the other targets. Each removed target gets a reason:

| Reason | When |
|---|---|
| `unresolvable` | a host name that does not resolve (NXDOMAIN, a resolver failure): an address the policy cannot check is never scanned |
| `wildcard_pattern` | a pattern such as `*.example.com`, not a host |
| `denied_by_policy` | outside `targets.allow`, in `targets.deny`, a private address without the switch, the built-in deny list, or a port outside `ports.allow` |
| `invalid_target` | not a URL, host, address, range or path, or unsafe to hand to a tool |

The job then **completes** as partial. Its result lists every skipped target
(`refused_targets`: target, reason, rule, detail; at most 100, with
`refused_targets_total`), and the platform shows "Completed with N targets
skipped". The task's log has the policy check and one line per skipped
target. For example, `example.com` runs and `api.example.com` (NXDOMAIN) is
skipped:

```
Local policy check  targets=2 refused=1
Target refused by the local policy: api.example.com  reason=unresolvable rule=targets
Running on 1 of 2 target(s); 1 skipped
Completed with 1 target(s) refused: "api.example.com" (unresolvable)
```

**The whole job.** The job is refused, and nothing runs, in these cases:

- a job-wide rule refuses it (the kill switch, `checks.allow`, `tools.allow`,
  `allow_custom_templates`, `allow_interactsh`, a `ports` setting);
- every target is refused;
- the single target of a single-target tool is refused;
- one target of a retest or a validation is refused.

The job is then reported **failed** with a reason the platform shows. The
task's log has the same lines, so "no logs" never hides a refusal. Examples:

```
refused by local policy: targets.deny: 203.0.113.9 (resolved from db.example.com) is in 203.0.113.0/24
refused by local policy: targets.allow: 192.0.2.1 is not in an allowed range
refused by local policy: ports.allow: port 22 is not in 80,443,8000-8999
refused by local policy: tools.allow: naabu is not allowed on this sensor
refused by local policy: allow_interactsh: the job asks for out-of-band callbacks (interactsh); this sensor's policy does not allow them
refused by local policy: kill_switch: kill switch file /etc/openctem/STOP is present
refused by local policy: targets: 2 target(s) refused: "api.example.com" (unresolvable), "*.example.com" (wildcard_pattern)
```

`sensor policy explain -target T` prints the rule and the per-target reason,
for example `rule targets (unresolvable)`.

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

A sensor without a policy works as sensors did before local policies existed:

- only the built-in deny list and `SENSOR_ALLOW_PRIVATE_TARGETS` limit targets;
- a job may enable out-of-band callbacks (interactsh), and custom templates
  run when `SENSOR_TEMPLATE_SIGNING_KEYS` is set (existing installs keep
  their behavior), with a warning in the log for each
  such job;
- it logs warnings at start and reports `local_policy: {"state": "absent"}`, so
  the platform can flag it.

New installs should always ship a policy. In a policy, custom templates and
interactsh are **off** unless the policy turns them on.

## Installing a policy

How to install a policy by hand. (Planned: the platform's sensor install
dialog offers the policy as a step of the install command, prefilled from
what the platform knows, such as a zone's ranges and the organization's
verified domains; the **network owner** edits and approves it, and the
platform never installs or changes it afterwards.)

1. Write the policy from [`sensor-policy.example.yaml`](sensor-policy.example.yaml).
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
     -e API_URL=https://openctem.example.com \
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
   send the sensor SIGHUP (or restart the pod), or name a `kill_switch_file` on a writable volume that
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
- A scanner resolves a host name again when it runs (DNS rebinding window).
  The sensor checks a name twice: at admission, and again right before the
  scanner starts. A name that resolves into a denied range by then is
  skipped (`denied_by_policy`). External scanners (nuclei, httpx, ...) then
  look the name up once more themselves. A name that changes its answer
  between that last check and the scanner's own lookup is caught only by the
  guarded dialer and the host firewall. To close the window, list addresses
  in `targets.allow` instead of names.
- An unresolvable dotless name (an image reference such as `alpine`) reaches
  no target network and is not checked against `targets.allow`.
