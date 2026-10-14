### Behaviour change: a Tenable.sc scan whose result is not imported fails

- A `connector_scan` now fails with the reason when Tenable.sc blocks the import (it would exceed the IP licence; the error names the licensed and active counts), when the import errors, or when the scan ends in `Error` with nothing imported. Before, the command completed with no findings, which read as "assessed, nothing found".

### Added: Tenable.sc scans report progress and per-target outcomes, and survive a sensor restart

- While a scan runs, the checks Tenable.sc completed are reported as liveness; at the end each target gets a CTIS outcome (`done`, `failed: unreachable` for a host that did not reply to a completed scan, `unfinished`) and a reach observation, and the result carries `total_ips`/`completed_ips`.
- After a restart the sensor follows the scan it already launched for the same command (found by its name `openctem-<command id>` in the job's repository) instead of launching a second one.
- `cmd/tenablesc-mock`: a Tenable.sc API mock for scratch end-to-end runs (not in the image).

### Fixed: Tenable.sc scans launched from OpenCTEM no longer fail at admission

- The platform adds its run keys and per-host politeness keys (`scan_run_id`, `scan_run_step_id`, `host_keys`) to every `connector_scan` payload; the connector's strict payload check refused them, so every scan launched from OpenCTEM failed with `unknown field "host_keys"`. They are now accepted and ignored; any other unknown key is still refused.
