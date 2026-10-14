### Fixed: one refused target no longer fails the whole scan task

- The sensor's target guard refused a whole task on its first bad target (live: an HTTP probe step failed with `scan target refused by guard: DNS lookup failed for scanner target "104.17.85.188:80"`, and the next step was skipped). The guard now runs per target in the sdk-go executor: a refused target is left out and listed in the result with its reason (`refused_targets`, rule `target_guard`, outcome skipped/refused), the other targets run, and the task fails only when every target is refused.
- `host:port` targets (`203.0.113.7:80`, `[2001:db8::1]:443`) are checked on their host.

### Changed: the target guard lives in the sdk-go core

- The guard is the sdk-go scan-target policy (`ByScanner`): the same rules (blocked metadata, loopback, CGNAT, multicast and reserved space; RFC1918/ULA only with `SENSOR_ALLOW_PRIVATE_TARGETS=1`; http/https only; a name that does not resolve is refused; code-scanner paths confined to `SENSOR_SCAN_ROOTS`). Its blocked set is the SDK's, which also covers NAT64, 6to4, Teredo, `192.0.0.0/24` and `198.18.0.0/15`.
