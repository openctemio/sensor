### Added: naabu implements discover.hosts@1 (host discovery)

- A `discover.hosts@1` job runs naabu as host discovery: a TCP connect probe of a few common ports (80, 443, 22, 3389, 8080, 8443, unless the job's `ports` param or the scan's settings name others), on addresses and ranges. Each address that accepts a connection on one of them is reported as a live `ip_address` with the probe that answered in `properties.live_by` (`tcp:443`); nothing else is reported. The tool sandbox grants no raw sockets, so ICMP echo is not used.
- `scan.ports@1` jobs are unchanged.
- ctis is bumped to the taxonomy with `discover.hosts@1`.
