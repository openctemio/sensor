### Fixed: recon tasks report progress target by target

- Out of process (the default), a recon tool (httpx, naabu, dnsx, subfinder, katana) settled its targets only after the last one ended, so the task's progress read 0 done for the whole run. The platform took long httpx tasks back as stalled and finally failed them (2026-10-14). Each target is now settled the moment it ends, and the heartbeat's progress moves with it.

### Behaviour change: one target never fails a recon task

- A target over its time budget, or one the tool could not reach, is that target's outcome: it is listed in the report's `failed_targets` with a `timeout` or unreachable class. The task completes, also when that target is the only one. The task fails only when the tool itself failed on every target, for example a usage error or a binary that does not run.
- When the job's time budget ends a recon run, the finished targets' results are kept: the report is partial and lists the targets not reached in `unfinished_targets`. Out of process this needs sdk-go with partial delivery on a stop. A cancel still discards the run.
