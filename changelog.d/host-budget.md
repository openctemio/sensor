### Behaviour change: one target host never gets more than the job's budget

- Every scan job now runs under a per-host budget, Standard by default: 20 requests per second and 8 in flight per target host, counted per host whatever the scheme, port or path of the job's targets. See "Per-host budget" in `docs/REFERENCE.md`.
- With the tool sandbox on, the task's forwarder enforces it for nuclei, httpx and katana whatever their flags say. Before, the forwarder's per-host ceiling was the job's whole rate: one host of an eight-host nuclei job could get 150 requests per second, and httpx and katana had no per-host bound at all.
- The tools' flags follow the same budget. A `rate_limit` or `concurrency` a person set above the budget (the organization's, the sensor's or the scan's settings, or the sensor's scanner config) is now lowered to it; before, it replaced the pacing level. To run faster on hosts you own, set `SENSOR_PACING_LEVEL=fast`.
- httpx over a list of one host's URLs runs at that host's budget (`-rl 20 -threads 8`), not at the sweep rate of 50.
- With `SENSOR_SANDBOX=off` a tool whose rate flag is global to its process (nuclei, httpx, katana) gets one host's budget for the whole run. Runs over several hosts are slower there; the sandbox is the way to get per-host enforcement and the full rate.
- A host that answers nothing but 429 or 503 five times in a row is paused and reported as a coverage gap `throttled` with counts; the run completes partial and keeps what the tool delivered.

### Added: operator ceiling, sensor level, signed budgets and a canary for HTTPS

- `SENSOR_PACING_LEVEL` (`gentle`, `standard`, `fast`): the level of jobs that carry no signed budget.
- Local policy keys `rate.max_host_rps` (1 to 200) and `rate.max_host_inflight` (1 to 50): the per-host ceiling no job passes. A budget above it is lowered and the job's log says so.
- The sensor reports the capability `pacing.budget@1` and reads the per-host budget of a job's signed statement. A platform that sends none needs no change.
- A canary request (`GET /` per target origin, every 10 seconds) makes 429, 503, `Retry-After` and block pages visible on HTTPS without terminating TLS, and stops an unconfined tool whose every host pushes back.
- A job's result (`metadata.target_rate`) and log carry the budget, the back-off and breaker counts and the hosts that pushed back.
