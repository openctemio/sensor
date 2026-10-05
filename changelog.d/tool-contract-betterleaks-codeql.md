### Added: betterleaks and codeql run out of process, on the tool contract

- Dispatched betterleaks scans and codeql scans run in the task sandbox as
  `openctemio-sensor __openctem-tool <name>`, like trivy and semgrep: the
  report comes back as a checked artifact and the sensor parses it with the
  scan's asset, branch and commit as before (parity tests compare both
  paths). betterleaks declares no network at all.
- A configured CodeQL database path is resolved by the sensor and is the
  child's only extra write path.
- Both manifests are listed by `openctemio-sensor tools manifests [--json]`.
