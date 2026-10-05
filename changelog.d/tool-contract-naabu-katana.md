### Added: naabu and katana run out of process, on the tool contract

- naabu and katana join httpx, subfinder and dnsx: each scan runs in the
  task sandbox as `openctemio-sensor __openctem-tool <name>`, and the sensor
  checks and stamps every record. The CTIS output is unchanged (golden
  parity tests compare both paths).
- naabu runs as a TCP connect scan and declares no Linux capabilities (the
  sandbox grants none). A scan configured as a SYN scan, which needs raw
  sockets, stays in the sensor process as before. A scan's naabu settings
  (ports, rate, retries) are applied by the sensor before the child starts.
- Both manifests are listed by `openctemio-sensor tools manifests [--json]`.
