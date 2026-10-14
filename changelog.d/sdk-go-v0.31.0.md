### Changed: a running task frees each host as soon as its targets finish

- Built on sdk-go v0.31.0. While a task runs, each host is released as soon as its targets settle, and the freed hosts are reported on the heartbeat. The platform can then start the next scan on that host straight away instead of waiting for the whole task. Nothing to configure.
