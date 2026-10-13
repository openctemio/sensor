### Behaviour change: host discovery probes only the ports the platform names

- naabu's `discover.hosts@1` run builds its report with sdk-go's `core.LiveHostsReport`, which also drops any address the job did not name.
- The sensor no longer has its own probe port set: a host discovery job without probe ports is refused (`core.ErrNoProbePorts`). The platform names them in every such job (api RFC-088).
- sdk-go is bumped.
