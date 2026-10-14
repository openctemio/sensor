### Changed: naabu scans a target list in one run

- A naabu task with several targets runs one naabu process for the whole list (`-l`) instead of one process per target in sequence: naabu's workers, rate limit and per-probe timeout apply across the list, and a host that does not answer costs only its own probes, not a process start and a per-target kill. Each open port is attributed to the input target that names its host, is its address, or is the range that contains it; a record that belongs to no target is dropped.
- The job's concurrency now reaches naabu as `-c` (it was never passed, so naabu always ran 25 workers whatever the job asked).
- A target naabu prints nothing for (no open port, or a name that does not resolve) settles with no result instead of failing on its own; naabu skips such hosts itself. A run that fails as a whole (bad flag, no valid targets at all) still fails the task.
- When the job's budget ends the run, the targets with records are kept and the others are listed as unfinished.
- Single-target tasks keep the per-target run. The recon runner takes any tool that implements a batch run (`recon/batch.go`), so the other recon tools can follow.
