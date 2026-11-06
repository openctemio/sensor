### Changed: sdk-go v0.48.0

- Sensor on sdk-go v0.48.0 (and contract v1.5.1): the signed pairing grant,
  a stored report that states the lease epoch it was made under, the control
  channel's last-known-good platform address (`SENSOR_CONTROL_DNS_MAX_STALE`,
  default `24h`, `0` turns it off), `allow_private` on every local policy
  report, the isolation level in tool manifests and proven isolation backends.
- A sensor whose `SENSOR_SANDBOX=auto` cannot enforce the tool sandbox now
  refuses tools that contact their targets (`unconfined_sandbox`) instead of
  running them with a warning. Passive lookups still run;
  `SENSOR_SANDBOX=off` stays the explicit acknowledgement.
