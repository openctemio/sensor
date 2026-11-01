### Added: the sensor owner can mark this sensor's scan traffic with headers

- Local policy `http.headers` (up to 4) is exposed: a ready example (`docs/sensor-policy-headers.example.yaml`),
  the rules and the merge with the platform's headers in `docs/LOCAL_POLICY.md`, and in the multi-sensor kit
  `./sensors.sh set-header NAME HEADER VALUE` and `unset-header NAME HEADER` (the policy keeps its scope; the container is recreated).
- `http.identity@1` now covers the whole feature (there is no `@2`): the platform's locked header names are honored, each result reports what was sent,
  and a job's query parameter is reported "not applied" by nuclei, httpx and katana (they have no flag for it).
- Behaviour change: while the owner sets headers, a networked tool that cannot carry headers is refused for every job.
