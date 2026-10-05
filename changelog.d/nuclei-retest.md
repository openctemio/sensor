### Added: the platform's retests of nuclei findings

- The sensor serves the platform's `retest` command for nuclei findings and advertises `retest:nuclei` (with `validate:nuclei`). In its sandboxed child, the `nuclei-validate` tool first checks each address with a TCP connect, then re-runs each finding's own template with the re-verification's safety flags (one signed template, destructive classes excluded, rate ceiling). A finding whose template matches again is `still_present`. One whose template ran against the reachable address and did not match is `fixed`. Anything else (an unreachable address, a template that is not installed or is excluded, a nuclei error) is `unverifiable`, never `fixed`. The platform closes or reopens findings from these verdicts.
- Every address passes the local policy (as for a scan) and the validate guard (no loopback, link-local or cloud-metadata target) before nuclei runs.

### Upgrade notes

- A local policy that lists `checks.allow` must add `retest` for the sensor to accept retests (see `docs/sensor-policy.example.yaml`).
