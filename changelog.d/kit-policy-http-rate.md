### Fixed: the local policy's http and rate settings apply to the built-in tools

- `http.allow_insecure_tls: false`, `http.user_agent`, `http.headers` and `rate.max_rps` in the sensor's local policy were silently ignored for tasks the daemon runs through the tool host (nuclei, httpx, katana and the other ported tools). They now apply at every task, and a policy reload (SIGHUP) takes effect at the next task.
- Each setting only narrows what a job asks for: a job's rate above `rate.max_rps` is lowered (a job that sets no rate runs at the maximum), `allow_insecure_tls: true` is the default and never lifts the organization's own refusal, and headers the platform locks keep the platform's value. Credential, cookie, host, proxy and connection headers are refused when the policy loads, as before.
- Operators who set these keys will see them take effect after the upgrade: check that `rate.max_rps` and `http.allow_insecure_tls` are what you want.
