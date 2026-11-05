# Sensor profiles

A profile is a sensor image built for one intrusiveness ceiling. Pick the profile that matches what the sensor is
allowed to do; the platform places work by what the sensor reports, so a profile never needs a setting on the
platform.

| Profile | Image | Tools | Tier ceiling | Use it for |
|---|---|---|---|---|
| passive | `ghcr.io/openctemio/sensor:<version>-passive` | subfinder; rdap and asn (compiled in) | T0 | discovery that must never send a packet to a target |
| standard | `ghcr.io/openctemio/sensor:<version>-standard` (also `:<version>` and `-default`) | nuclei with the pinned templates, subfinder, dnsx, naabu, httpx, katana; rdap and asn | T1 | external attack surface discovery and checks (the default) |
| full | `ghcr.io/openctemio/sensor:<version>-full` | every tool of standard plus semgrep, betterleaks and trivy | T1 | one sensor for discovery and code, dependency and image scanning |
| browser | `ghcr.io/openctemio/sensor:<version>-browser` | every tool of standard plus webshot (headless Chromium) | T1 | screenshots of web origins (web evidence), opt-in |

The per-tool images (`-semgrep`, `-opengrep`, `-trivy`, `-betterleaks`, `-nuclei`) stay for one-shot and CI use.

Every profile image is multi-arch (linux/amd64, linux/arm64), carries an SBOM and a build provenance attestation, and
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
- a page has `page_timeout` seconds; then its scripts are stopped and the picture is taken; dialogs are dismissed;
- the picture is the 1280x800 viewport, or the page down to 2400 pixels (`full_page`), decoded and encoded again
  (PNG, or JPEG when larger; no metadata survives), at most `max_image_kb` KiB;
- one browser per task with its profile in the task directory, removed with the task; one fresh browser context per
  target.

Chromium comes from Debian's security archive at a pinned version (`io.openctem.sensor.chromium` label). Chromium has
a stable security release about every week; a sensor release bumps the pin, and the weekly image scan reports a
version with known CVEs. Update the browser image as you update the browser on a workstation.

## Moving between profiles

All the profile images run as uid 999 with the data volume at `/var/lib/openctem`, so a sensor keeps its identity,
outbox and content when its image changes: stop it, start the other image with the same volume. The sensor reports the
tools it now has on its next heartbeat; work for tools it no longer has goes to other sensors.
