### Added: nuclei's performance options are declared and settable

- nuclei's manifest declares `rate_limit`, `concurrency`, `bulk_size`, `timeout`, `retries`, `max_host_errors` and `scan_strategy`, each with its default (nuclei's own), bounds and native flag (`x-octm-flag`). `rate_limit`, `concurrency`, `timeout` and `retries` are the common tool options (`x-octm-common`), so the platform's per-job decision and the per-target budget reach them through the SDK (the budget shortens `-timeout`).
- Only the sensor's settings may raise rate, concurrency or retries above the default; a scan or the job's decision may only lower them; `bulk_size` is a sensor setting only. The operator's `SENSOR_NUCLEI_MAX_*` ceilings still cap whatever the settings say.
- Resolved settings replace the command's raw `rate_limit`/`concurrency`/`bulk_size` (the SDK already fitted them into the settings); without settings the arguments are exactly as before.
- naabu's manifest marks `rate` and `retries` as common options and names the native flag of every option.
- New tests check that every option with a native flag in the manifest reaches the tool's argument list as that flag.
