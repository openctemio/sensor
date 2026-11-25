# Sensor profiles

A profile is a sensor image built for one intrusiveness ceiling. Pick the profile that matches what the sensor is
allowed to do; the platform places work by what the sensor reports, so a profile never needs a setting on the
platform.

| Profile | Image | Tools | Tier ceiling | Use it for |
|---|---|---|---|---|
| passive | `ghcr.io/openctemio/sensor:<version>-passive` | subfinder; rdap and asn (compiled in) | T0 | discovery that must never send a packet to a target |
| standard | `ghcr.io/openctemio/sensor:<version>-standard` (also `:<version>` and `-default`) | nuclei with the pinned templates, subfinder, dnsx, naabu, httpx, katana; rdap, asn, webguess and svcdetect | T1 | external attack surface discovery and checks (the default) |
| full | `ghcr.io/openctemio/sensor:<version>-full` | every tool of standard plus semgrep, betterleaks and trivy | T1 | one sensor for discovery and code, dependency and image scanning |
| browser | `ghcr.io/openctemio/sensor:<version>-browser` | every tool of standard plus webshot (headless Chromium) | T1 | screenshots of web origins (web evidence), opt-in |
| relay | `ghcr.io/openctemio/sensor:<version>-relay` | none: the sensor binary only (feed relay, `feed.relay@1`) | none: no scan capability | relaying the platform's signed feeds for a platform without outbound access |

Every profile but relay also carries the CT lookup (`ctlog`, capability `lookup.ct@1`, tier T0), compiled into the sensor runtime.
It is served only by a shared (platform) sensor with a pinned job-signing key (`SENSOR_CT_LOOKUP`, see
[REFERENCE.md](REFERENCE.md)): the platform asks it which certificates Certificate Transparency lists for an
organization's root domain, so the platform itself needs no outbound access. It asks crt.sh and Cert Spotter only and
never sends a packet to the domain's hosts. Answers are read one record at a time: a source whose answer has more
records than the cap, a record over 2 MiB, or a Cert Spotter list longer than its page limit is `too_large` (remembered
per organization and domain until the cache expires), and an empty crt.sh answer is `unavailable`. A 429 or
Retry-After cools a source down for at most 15 minutes.

The per-tool images (`-semgrep`, `-opengrep`, `-trivy`, `-betterleaks`, `-nuclei`) stay for one-shot and CI use.

Every profile image (relay included) is multi-arch (linux/amd64, linux/arm64), carries an SBOM and a build provenance attestation, and
is signed with cosign keyless by the release workflow (verify it as the README shows). Each names its profile in the
label `io.openctem.sensor.profile`.

## The passive guarantee

The passive image holds no program that can actively touch a target, not only no active tool turned on:

- it contains only tools of tier T0 whose every program is passive. `dnsx` is left out because `dnsx-enum`
  (`enumerate.subdomains`, T1) runs the same binary;
- the release smoke test reads the compiled-in tool manifests, takes the program (engine) of every tool above T0 or
  with a declared side effect, and fails the build if any of them is in the image. A new active tool is covered without
  editing the test;
- the tools the daemon detects in the image must all be T0.

The platform enforces tiers on its side as well (grants and the scan's tier); the local policy can lower the ceiling
further. The passive image is the guarantee that holds even if both were wrong.

## The relay profile

The relay image is a sensor that does one job: it relays the platform's signed feeds (the vulnerability feed with its
KEV and EPSS data, the release feed) when the platform has no outbound access (api RFC-142, "feed relay"). The
platform asks its designated relay sensors for the feed files, each relay downloads them from the official feed
origins and streams them back, and the platform verifies every file against the feed's own pinned root, so the relay
adds no trust. The relay image carries no tool: no subfinder, no nuclei, no Python, no shell. The static sensor binary
on a distroless static base is its only program, and it runs as uid 999 on a root filesystem it never writes (the data
volume at `/var/lib/openctem` and a tmpfs at `/tmp` are its only writable paths).

Use it when:

- the platform runs without outbound access (an internal network, a locked-down cluster) and its feeds come through
  relay mode (Console > System > Feed delivery);
- you do not want the relay to be a scanning sensor: a host that scans targets and a host that fetches the feeds are
  separate jobs, with separate network rules.

Run one to three of them for redundancy (the platform designates at most three relay sensors and uses any one that is
online), on hosts in different failure domains if you can.

What the image does and does not do:

- it must be a shared sensor of the instance (enrolled with an instance enrollment token, `SENSOR_SHARED_MODE=1`)
  with a pinned job-signing key or root, like every relay. The feed relay is required: a relay sensor that cannot
  relay (an organization's sensor, no pinned key) or with `SENSOR_FEED_RELAY=0` refuses to start and says why;
- it registers no tool, reports no tool and no capability but `feed.relay@1`, and withdraws the shared isolation
  capability (`shared.isolation@1`). The platform places work only by what a sensor reports (a job's required
  capabilities, the tool it names, and the shared isolation profile for every shared job), so it never offers a scan
  to a relay sensor; the sensor also accepts no command but the health check, in case one were offered;
- it serves no CT lookup (`lookup.ct@1`): CT monitoring stays with a standard shared sensor, and
  `SENSOR_CT_LOOKUP=1` on a relay sensor refuses to start. A relay contacts the feed origins only;
- shared mode still requires its sandbox, network confinement and a local policy, so run it like any shared sensor
  (the sensor's seccomp profile, no capabilities, `no-new-privileges`), with less memory and CPU: about 256 MiB and
  half a CPU are enough.

Network: the relay needs HTTPS to the platform and HTTPS to the feed origins, nothing else. The official origins are
`https://github.com/openctemio/vulnfeed-bundles/releases/latest/download` and
`https://github.com/openctemio/openctem/releases/latest/download` (GitHub redirects the downloads to its release asset
host, `release-assets.githubusercontent.com` and `objects.githubusercontent.com`); a mirror you list in
`SENSOR_FEED_RELAY_ORIGINS` (and in the platform's job signer allowlist) adds its own. Allow egress to those names on
443 and refuse the rest; the relay never connects to a scan target.

The release smoke test proves the profile on every build: the sensor binary is the only executable file in the image,
`tools manifests` is empty, the daemon refuses to start as an organization's sensor because the relay is required, and
`SENSOR_CT_LOOKUP=1` is refused.

## The browser profile

The browser image adds the `webshot` tool (capability `capture.screenshot@1`): headless Chromium loads a web origin and
the sensor reports the picture with the page's status, title and server, as the origin's web evidence (the platform
keeps it only when the organization turned screenshots on). The default image carries no browser: a browser is large
(about 300 MB more) and runs the target's scripts, so it is a choice the sensor's owner makes by picking this image.

The image requires the full task sandbox and refuses to start without it (`SENSOR_SANDBOX=required` and
`SENSOR_SANDBOX_NETWORK=required` are set in the image). Run it with the seccomp profile it prints
(`openctemio-sensor seccomp-profile`, which allows `chroot` for Chromium's sandbox; see docker/seccomp/README.md), no
capabilities and `no-new-privileges`, as for every sensor image:

- every capture runs in a task whose network namespace leads only to the task's egress forwarder, which admits the
  job's targets alone and resolves names itself; the browser resolves nothing;
- the tool runs as a non-root user of its own user namespace, and Chromium's own sandbox stays on: its renderers run
  in Chromium's namespaces and seccomp policy inside the task sandbox (the browser never starts with `--no-sandbox`);
- every request is checked before it leaves the browser: http and https only, GET and HEAD only, the job's targets and
  web scope only, at most `max_requests` per page; WebSocket, WebTransport and WebRTC are removed from pages, and
  downloads, the file chooser, permission prompts and new windows are off;
- web workers never run: a dedicated worker's requests cannot be checked before they leave the browser, and shared
  and service workers are refused by policy, so each worker stays paused before its first line of script until the
  page is closed (a page that needs a worker to draw is pictured without it);
- a page has `page_timeout` seconds; then its scripts are stopped and the picture is taken; dialogs are dismissed;
- the picture is the 1280x800 viewport, or the page down to 2400 pixels (`full_page`), decoded and encoded again
  (PNG, or JPEG when larger; no metadata survives), at most `max_image_kb` KiB;
- one browser per task with its profile in the task directory, removed with the task; one fresh browser context per
  target.

Chromium comes from Debian's security archive at a pinned version (`io.openctem.sensor.chromium` label). Chromium has
a stable security release about every week; a sensor release bumps the pin, and the weekly image scan reports a
version with known CVEs. Update the browser image as you update the browser on a workstation.

## Moving between profiles

All the profile images (relay included) run as uid 999 with the data volume at `/var/lib/openctem`, so a sensor keeps its identity,
outbox and content when its image changes: stop it, start the other image with the same volume. The sensor reports the
tools it now has on its next heartbeat; work for tools it no longer has goes to other sensors.
