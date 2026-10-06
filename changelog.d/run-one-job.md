### Added: run one job and exit (-job, SENSOR_JOB_ID)

- `-job <command id>` (or `SENSOR_JOB_ID`) runs the one platform command with that id and exits: one sensor pod per job (Kubernetes Job). It implies `-daemon -enable-commands`, sets up as a daemon does, claims the command by id, runs it with every check a polled command gets, waits for its results to be delivered, and exits 0. It exits non-zero when the claim is refused, the job is not run (it is released for another sensor), or results are not delivered in time. Mount the outbox on a persistent volume for such pods.
