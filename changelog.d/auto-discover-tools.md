### Behaviour change: the daemon with platform commands is the default mode

- A sensor started with no mode flag runs the daemon and takes platform commands, so a minimal `docker run` needs only `SENSOR_API_URL`, a state volume and (optionally) `SENSOR_PAIRING_CODE` or `SENSOR_API_KEY`. A run is one-shot when `-tool`, `-target`, `-push`, `-json` or `-output` is given, with `-daemon=false`, or in a CI job (`CI=true`, as the per-tool images set).
- `sensor.enable_commands: false`, `-enable-commands=false` and `-standalone` still turn platform commands off. **Upgrade note:** a config-file daemon that left `enable_commands` unset to run scheduled scans only now polls the platform (and pairs on first start when it has no key); set `sensor.enable_commands: false` to keep it scheduled-only. A bare start without `SENSOR_API_URL` now exits 2 with the credentials help instead of "No scanners configured".
- The default image's command is now `-verbose`; a deployment that still passes `-daemon -enable-commands` behaves the same.

### Behaviour change: tools are auto-discovered

- The daemon enables every native tool whose wrapper is in this build and whose binary passes its check, from one table that tool detection, scanner construction and `-list-tools` share. The hard-coded detection list is gone.
- The tools list is no longer passed to the SDK as an allowlist, so `-tools` / `SENSOR_TOOLS` no longer silently drops `reach-probe`, `rdap` and `asn`. Narrow every tool, built-ins included, with the local policy's `tools.allow`.

### Deprecated: `-daemon`, `-enable-commands`, `SENSOR_TOOLS` / `-tools` in the daemon

- They still work for one release, each with a warning. In the daemon, `SENSOR_TOOLS` / `-tools` only narrows the detected tools: a listed tool that is not installed is ignored, named in the log and in a `config.tools_deprecated` check, and never advertised. One-shot runs take the list as before.
- `-enable-recon`, `-enable-vulnscan`, `-enable-secrets`, `-enable-assets`, `-enable-pipeline` and `-bootstrap-token` are now ignored with a warning instead of silently.

### Changed: sdk-go with `SENSOR_PAIRING_CODE`

- The sensor's SDK reads `SENSOR_PAIRING_CODE`: a sensor with no identity attaches to that code on first start (ignored once paired; never logged).
