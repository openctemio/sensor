### Added: the relay profile image (`-relay`)

- `ghcr.io/openctemio/sensor:<version>-relay` is a sensor that only relays the platform's signed feeds (feed relay,
  for a platform without outbound access). It carries no tool at all: the static sensor binary on a distroless static
  base is its only program. It reports `feed.relay@1` and nothing else (no tool, no scan capability, not the shared
  isolation profile), so the platform never places a scan on it, and it accepts no command but the health check.
- The feed relay is required in this image: a sensor that cannot relay (not a shared sensor of the instance, no pinned
  job-signing key) or with `SENSOR_FEED_RELAY=0` refuses to start; it serves no CT lookups (`SENSOR_CT_LOOKUP=1` is
  refused). Run one to three of them for redundancy (docs/PROFILES.md, "The relay profile").
- Built, smoke-tested, signed (cosign keyless), with an SBOM and a provenance attestation, like the other profiles. The
  smoke test fails the build if any executable file other than the sensor is in the image.
