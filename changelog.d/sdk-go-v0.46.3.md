### Changed: sdk-go v0.46.3 (fewer hosts reported as not fully covered)

- The sensor builds on sdk-go v0.46.3. A reset from a host that already answered halves the request rate instead of opening the circuit breaker, names that do not resolve are reported as `unresolvable` (not `denied_by_policy`), the sensor no longer claims job slots it cannot fill, and the egress log names the root DNS query.
