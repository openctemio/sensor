### Added: the tools' performance options are declared and settable

- nuclei's manifest declares `rate_limit`, `concurrency`, `bulk_size`, `timeout`, `retries`, `max_host_errors` and `scan_strategy`, each with its default (nuclei's own), bounds and native flag (`x-octm-flag`). `rate_limit`, `concurrency`, `timeout` and `retries` are the common tool options (`x-octm-common`), so the platform's per-job decision and the per-target budget reach them through the SDK (the budget shortens `-timeout`).
- Only the sensor's settings may raise rate, concurrency or retries above the default; a scan or the job's decision may only lower them; `bulk_size` is a sensor setting only. The operator's `SENSOR_NUCLEI_MAX_*` ceilings still cap whatever the settings say.
- Resolved settings replace the command's raw `rate_limit`/`concurrency`/`bulk_size` (the SDK already fitted them into the settings); without settings the arguments are exactly as before.
- naabu's manifest marks `rate` and `retries` as common options and names the native flag of every option.
- New tests check that every option with a native flag in the manifest reaches the tool's argument list as that flag.
- httpx, dnsx, subfinder and katana declare their rate, concurrency, request timeout and retries (as each tool supports them) as common options with native flags; the sensor's settings may raise rate and concurrency, a scan or the job's decision may only lower them, and the recon runner still lowers them to the job's limits. Their existing options name their native flags too.
- trivy declares `parallel` (`--parallel`, a sensor setting).

### Fixed: trivy no longer stops large scans after five minutes

- trivy gets `--timeout` equal to the run's bound; its own five-minute default ended big image and repository scans with "context deadline exceeded" long before the sensor's limit.
- trivy makes no calls to Aqua on a scan: `--disable-telemetry`, `--skip-version-check`, and `--skip-check-update` when the sensor manages trivy's database.
