### Security: every task of a ported tool is admitted against the local policy

- Before a ported tool's child starts (httpx, nuclei, subfinder, dnsx, naabu,
  katana, trivy, semgrep and the next ports), the task is admitted against
  the sensor-local policy in force at that moment: the kill switch,
  `tools.allow` (by the tool's name or the name it is configured under, such
  as `trivy-fs`), every target against the target guard, and the run time
  cap. A refused target is removed from the task, so the tool never sees or
  reaches it, and the report lists it under `refused_targets`
  (`refused_by_policy`); a task with no target left fails. A `SIGHUP` reload
  applies to the next task.
- Tasks carry the mode the sensor runs in (daemon, or runner for a CI run).
- sdk-go is pinned to its current main (per-task admission in the tool
  runtime).
