### Fixed: recon stays on the target's host and backs off when throttled

- katana runs with `-dr` (no redirects). Measured on katana v1.7.0 against
  two scratch hosts: with `-fs fqdn` alone, an in-scope link that redirected
  to the second host was still fetched there; filtering the results
  afterwards does not undo the request. In-scope links are still crawled.
- A scan's `rate_limit` and `concurrency` (capped by the local policy's
  `rate.max_rps`) only lower a recon tool's own limits: a scan asking for
  more than the tool's default no longer raises it, and `concurrency` now
  reaches the tool (`-threads` / `-c` / `-t`).
- A target answering 429 or 503 halves the rate of the job's later targets
  (down to 1 request/s) and waits 2 s, then 4 s, up to 30 s before the next
  one. The report says so: `target_throttled: true`, `throttled_targets`,
  `throttled_rate_limit`. No rotation or evasion.
- Extra args that would send a recon tool to other hosts are refused:
  `-fr`/`-follow-redirects`, `-fs`/`-field-scope`, `-cs`/`-crawl-scope`,
  `-ns`/`-no-scope`, `-dr`/`-disable-redirects` (any spelling).
