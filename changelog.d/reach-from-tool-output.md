### Added: job results say which targets the sensor could not reach

- httpx, naabu, nuclei and dnsx feed what they saw toward each target to the job's reach summary (`reach`, `unreached_targets` in the result metadata, sdk-go `pkg/reach`): no route, timeout, connection refused and names that do not resolve are told apart, and a scan with an unreached target completes as partial coverage instead of "nothing found".
- httpx runs with `-probe`: URLs that did not answer are read for their reason and are never reported as live hosts.
- Only the job's own targets are recorded, and an address only inside an address or range target.
