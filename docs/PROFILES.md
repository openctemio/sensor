# Sensor profiles

A profile is a sensor image built for one intrusiveness ceiling. Pick the profile that matches what the sensor is
allowed to do; the platform places work by what the sensor reports, so a profile never needs a setting on the
platform.

| Profile | Image | Tools | Tier ceiling | Use it for |
|---|---|---|---|---|
| passive | `ghcr.io/openctemio/sensor:<version>-passive` | subfinder; rdap and asn (compiled in) | T0 | discovery that must never send a packet to a target |
| standard | `ghcr.io/openctemio/sensor:<version>-standard` (also `:<version>` and `-default`) | nuclei with the pinned templates, subfinder, dnsx, naabu, httpx, katana; rdap and asn | T1 | external attack surface discovery and checks (the default) |
| full | `ghcr.io/openctemio/sensor:<version>-full` | every tool of standard plus semgrep, betterleaks and trivy | T1 | one sensor for discovery and code, dependency and image scanning |

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

## Moving between profiles

All three profile images run as uid 999 with the data volume at `/var/lib/openctem`, so a sensor keeps its identity,
outbox and content when its image changes: stop it, start the other image with the same volume. The sensor reports the
tools it now has on its next heartbeat; work for tools it no longer has goes to other sensors.
