### Added: subfinder and dnsx run out of process, on the tool contract

- subfinder and dnsx are ported to the tool contract like httpx: each scan
  re-executes the sensor as `openctemio-sensor __openctem-tool <name>` in the
  task sandbox, and the sensor checks and stamps every record (declared
  output types, limits, provenance). The CTIS output is unchanged (golden
  parity tests compare both paths).
- The sensor reads its DNS resolvers (`SENSOR_DNS_RESOLVERS` or
  `/etc/resolv.conf`) and hands them to the child, so the tools still never
  use their built-in public resolver lists.
- Both manifests are compiled in and listed by
  `openctemio-sensor tools manifests [--json]`; `SENSOR_TOOL_RUNTIME=in-process`
  still runs them in the sensor process (rollback switch).
- Each ported tool now registers itself in its own package, so porting the
  next tool touches only that package.
