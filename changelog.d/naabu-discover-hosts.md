### Added: naabu implements discover.hosts@1 (host discovery)

- A `discover.hosts@1` job runs naabu as host discovery: a TCP connect probe of the ports the platform names in the job, on addresses and ranges. The report is built by sdk-go's `core.LiveHostsReport`: each address of the job that accepts a connection is reported as a live `ip_address` with the probe that answered in `properties.live_by` (`tcp:443`); nothing else is reported. The tool sandbox grants no raw sockets, so ICMP echo is not used.
- The platform decides the probe: a host discovery job without probe ports is refused (`core.ErrNoProbePorts`); the sensor never picks its own set.
- `scan.ports@1` jobs are unchanged. ctis and sdk-go are bumped.
