### Added: scan traffic through the organization's proxy pools

- A scan or retest job may carry the organization's proxy pool: every connection of the job's confined tools goes through it (sdk-go `pkg/sensorkit/egress/upstream`), the scope check and per-target rate first, never direct. The sensor reports `egress.upstream@1` when its tools run out of process in a sandbox that confines their network and `SENSOR_SCAN_EGRESS` is not `direct-only`.
- New settings `SENSOR_SCAN_EGRESS` (`platform` or `direct-only`) and `SENSOR_SCAN_EGRESS_ALLOW` (accepted proxy endpoints); see docs/REFERENCE.md "Organization proxy pools", which also lists which built-in tools the pool carries.
- A pooled job is refused (`egress_unavailable`) on the in-process tool runtime and for a naabu SYN scan, whose traffic would not pass the forwarder.
- The pinned sdk-go carries the pool, the credential fetch and the end-of-job report.
