### Behaviour change: nuclei's rate adapts per host, and unresponsive hosts are coverage gaps

- A confined nuclei run passes its effective rate limit (the scan's
  `rate_limit`, lowered by scan windows, program rules and the local policy's
  `rate.max_rps`, capped at `SENSOR_NUCLEI_MAX_RATE_LIMIT`) to the task
  forwarder as the ceiling of its adaptive per-host rate: each host starts
  lower, backs off on 429/503, resets and timeouts, and never exceeds the
  ceiling. nuclei is not restarted to change its rate.
- nuclei runs with `-mhe 30` (the bounds table's per-host error budget). A
  host nuclei skips as unresponsive, and a host the forwarder's breaker gave
  up or that blocked the scan, no longer reads as "no findings": the command
  completes with partial coverage and its result lists the host under
  `coverage_gaps` with the reason (`breaker_open`, `rate_floor`, `blocked`).
