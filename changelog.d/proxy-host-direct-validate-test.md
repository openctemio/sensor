### Added: a direct-only sensor is reported, validate jobs go through the pool, and the sensor serves the proxy Test

- A sensor with `SENSOR_SCAN_EGRESS=direct-only` reports `egress.host-direct@1`, so the platform runs its scans direct instead of holding them (a shared sensor never reports it).
- Validate jobs (finding re-checks) leave through the job's proxy pool, the safe-check's connection and the nuclei re-verification alike, and the sensor reports `egress.validate@1`. A probe never goes direct: a pool that cannot be used fails the job, and a proxy failure ends the probe inconclusive, never "fixed".
- The sensor serves the platform's `proxy_test` command (`proxy.test@1`): it tests each endpoint of a pool through the platform's echo and reports the exit address, handshake time, IPv4 and IPv6, and whether the proxy only allows port 443.
