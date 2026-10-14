### Behaviour change: a Tenable.sc scan whose result is not imported fails

- A `connector_scan` now fails with the reason when Tenable.sc blocks the import (it would exceed the IP licence; the error names the licensed and active counts), when the import errors, or when the scan ends in `Error` with nothing imported. Before, the command completed with no findings, which read as "assessed, nothing found".

### Added: Tenable.sc scans report progress and per-target outcomes, and survive a sensor restart

- While a scan runs, the checks Tenable.sc completed are reported as liveness; at the end each target gets a CTIS outcome (`done`, `failed: unreachable` for a host that did not reply to a completed scan, `unfinished`) and a reach observation, and the result carries `total_ips`/`completed_ips`.
- After a restart the sensor follows the scan it already launched for the same command (found by its name `openctem-<command id>` in the job's repository) instead of launching a second one.
- `cmd/tenablesc-mock`: a Tenable.sc API mock for scratch end-to-end runs (not in the image).
