### Added: validation and retest jobs keep to the job's web scope

- The nuclei finding check (`nuclei-validate`, now 1.2.0) declares `features.web_scope`. Validation (`validate`) and retest jobs carry the job's `web_scope` like scans, so the platform no longer has to refuse them on hosts with a path exclusion.
- A web-scoped re-verify or retest runs only confined to the task's forwarder, which checks every request. nuclei goes through the forwarder's relay and leaves out the template types the forwarder cannot read as HTTP. Unconfined, the job is refused, never run unrestricted. An invalid scope fails the job.
- The safe-check validation only opens a TCP connection and requests no path, so the web scope does not change it.
