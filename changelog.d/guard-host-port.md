### Fixed: probes after a port scan are no longer refused as "no such host"

- A port scan hands the HTTP probe targets such as `203.0.113.7:80`. The sensor's target guard looked the whole string up in DNS and refused the task. It now checks the host part of `host:port` targets (IPv4, names and bracketed IPv6) with the same blocked-address rules.
