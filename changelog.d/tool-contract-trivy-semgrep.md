### Added: trivy and semgrep run out of process, on the tool contract

- Each trivy and semgrep scan runs in the task sandbox as
  `openctemio-sensor __openctem-tool <name>`. The scanner's report comes back
  as a checked artifact (confined to the task directory, size and digest
  verified) and the sensor parses it with the scan's asset, branch and commit
  exactly as before, so the findings are unchanged (parity tests compare both
  paths).
- A report larger than 64 MiB now fails the scan instead of being ingested;
  `SENSOR_TOOL_RUNTIME=in-process` restores the previous path.
- Registry credentials (`TRIVY_USERNAME` / `TRIVY_PASSWORD`) and `SEMGREP_*`
  settings still reach the tools only through the scanner environment, never
  through the task.
- trivy reports list their capabilities in a stable order.
- Both manifests are listed by `openctemio-sensor tools manifests [--json]`.
