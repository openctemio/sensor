### Fixed: a name that does not resolve no longer fails the whole scan job

- With sdk-go v0.41.0, a lookup-only DNS job reports each dead name on its own (reason unresolvable) and a job whose every name is dead completes per target, instead of the sensor refusing the whole command. Coverage of resolve.dns, scan.ports and templates stops failing on a batch that holds one gone name.

### Security: ports.allow covers top-N scans and capability parameters

- A capability job's params (`top_n`, `ports`) can no longer widen a port scan past the sensor's `ports.allow` (sdk-go #394, #397). The sensor also sends the report commit manifest and resumes held segments (sdk-go #396).
