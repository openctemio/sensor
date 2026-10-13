### Added: the reach probe (`reach.probe@1`)

- A daemon that runs commands serves the built-in `reach-probe` scanner and advertises `reach.probe@1`: on the platform's request it tests whether it reaches a job's targets with one TCP connect per address and port (443, 80, 22), no payload, no ICMP, and the result carries the job's reach summary (sdk-go `reach.Probe`, api RFC-089).
- It dials only through the local policy (admitted targets, `targets.allow`/`deny`, `ports.allow`, built-in deny list), at most 10 connects per second and 256 addresses per job. It refuses to run without a policy object, for a T0-only job, a web scope or port limits. A policy with `tools.allow` must list `reach-probe`.
- The probe passes the SDK's reach conformance suite, and the sensor with it passes the sensor conformance suite.
