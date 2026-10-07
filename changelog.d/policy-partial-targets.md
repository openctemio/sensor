### Behaviour change: one refused target no longer fails a scan job

- A scan target the local policy refuses, or cannot check, is skipped, and the job runs on its other targets. "Cannot check" means the name does not resolve or the target is a wildcard pattern. The job completes as partial and lists every skipped target with a reason: `unresolvable`, `wildcard_pattern`, `denied_by_policy` or `invalid_target`. The platform shows "Completed with N targets skipped".
- The job still fails, with the list, when every target is refused or when the single target of a single-target tool is refused. Retest and validation jobs are still refused whole.
- An address the policy cannot check is never scanned.
- The task log now shows the sensor's own lines: received, the policy check and each skipped target, the outcome, and a hand-back to the platform. A job refused before any tool started has a log saying why.
- `sensor policy explain` prints the per-target reason, for example `rule targets (unresolvable)`.

### Changed

- sdk-go is pinned to the commit with per-target admission (sdk-go #191).
