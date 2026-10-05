### Fixed

- Recon tools (subfinder, dnsx, naabu, httpx, katana) run at the scan's
  rate limit (the command's `rate_limit`, capped by the local policy's
  `rate.max_rps`). It was dropped and every run went at the tool's default.
