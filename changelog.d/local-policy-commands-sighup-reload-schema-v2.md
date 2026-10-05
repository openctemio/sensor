### Added: local policy commands, SIGHUP reload, schema v2

- `openctemio-sensor policy validate|digest|explain|install`: check a policy
  with the sensor's own loader, print the digest the sensor reports, ask
  whether a job would be admitted and by which rule it is refused, and
  install a reviewed file (`--expect-sha256`, refused on a mismatch, an
  invalid policy, a symlink destination or a directory anyone can write;
  atomic 0644 write; `-pid` sends SIGHUP). Local files only.
- SIGHUP reloads the local policy (owner decision D10). A file that does not
  load engages the kill switch until a later reload loads a valid one; the
  sensor never keeps the previous policy silently. The validating executor
  and the Tenable.sc scan executor follow the reload.
- Local policy schema v2 (sdk-go): every v1 key plus `managed.accept`; v1 is
  frozen (owner decision D13). The sensor reports the schemas it reads.
- The absent-policy warning says what actually happens: jobs may enable
  out-of-band callbacks, and custom templates run only when
  `SENSOR_TEMPLATE_SIGNING_KEYS` is set.
