### Added: subdomain brute force with dnsx (`dnsx-enum`, capability `enumerate.subdomains@1`)

- New tool `dnsx-enum` (tier T1, runs the same `dnsx` binary) brute-forces the subdomains of a root domain with the label list the platform names in the signed job (content slot `labels`, purpose `dns-labels`). The sensor has no list of its own: a job without one is refused. Only names that resolve are reported, wildcard zones are filtered, and a name outside the root or under an excluded host is never reported.
- Polite by default: 50 queries per second, 50 threads; a scan may only lower the rate (the sensor settings may raise it to 500 at most), and `max_queries` cuts the list. The resolver `dnsx` stays T0, so passive jobs are unaffected.
- Needs the platform to send the capability and the list; see docs/REFERENCE.md.
