### Changed: pairing retries, tool watchdog and clearer failures

- Pairing retries with backoff inside the process, and says plainly when the clock is skewed or the platform is rate limiting, so an install no longer needs a manual restart.
- Every tool run is watched and the platform deadline is its time budget, so a stuck run ends instead of holding its slot.
- Egress connections are bounded and never outlive their task.
- A proxy failure is reported as a coverage gap, not as an empty result.
- Warnings are written in plain language and no longer mention internal details.
