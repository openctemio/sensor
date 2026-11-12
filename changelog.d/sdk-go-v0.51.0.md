### Security: a job's own files are readable by that job's tool runs only

- The tool sandbox leaves the system's temporary directory readable to every task. The sensor kept a job's own files there: the rewritten copy of an organization's semgrep and opengrep rules, nuclei's signed copy of the custom templates (with any auth header in them), betterleaks' merged rule config, the target lists of nuclei, httpx, naabu and dnsx, dnsx's label and host lists, the report a semgrep, opengrep, betterleaks or CodeQL run writes, and a CodeQL database. On a shared sensor, a task of another organization launched while the job ran could read them.
- They now go into a private directory under the task root, which the sandbox hides from every task, and only the tool runs of the job that owns them are granted it. nuclei's configuration directory (it writes a resume file there) moved under the task root too.

### Security: ports.allow is checked at connect time

- The sensor's local policy now hands `ports.allow` to the egress forwarder, so a confined tool cannot connect to another port, whatever its settings or a redirect say. Before, the connect-time check was off and only admission held the ports.

### Upgrade notes

Check these before upgrading a sensor to this release (sdk-go v0.51.0):

- **Platform first.** Run a platform release that fills the `ports` of port-scan jobs from the sensor's `ports.allow` (or the job's own list) and that signs every command type when it advertises signed jobs. With `ports.allow` set, a port scan that names no ports is refused (rule `ports.allow`).
- **Sensors that bound their own key** (started with `SENSOR_API_KEY`, `SENSOR_KEY_BIND=auto`, the default) pin the platform's job signer at their first start over https, log "Job signer pinned on first use", and from then on REQUIRE signed jobs: an unsigned command is refused with `job_signature`. If your platform does not sign every command type, set `SENSOR_REQUIRE_SIGNED_JOBS=false` before upgrading, or upgrade the platform first.
- **Plain-http platform URLs are not pinned.** With an `http://` `SENSOR_API_URL` nothing is pinned and every start warns; signed jobs stay off and jobs that require secrets (proxy pool credentials, authenticated scans) are refused with `secrets_unverified`. Use an https URL, or set `SENSOR_JOB_SIGNING_ROOT`.
- **Redirects are refused** by every platform and relay client, including protocol v3 over gRPC and HTTPS: set `SENSOR_API_URL` to its final address.
- **Recovery** if the platform later moves to a signer the pin does not cover (jobs refused with `job_signature`): set `SENSOR_JOB_SIGNING_ROOT` to the job-signing root shown in the console, or remove `job_signing_keys` (or `job_signing_root`) from `identity.json` in the state directory and restart over https.

### Behaviour change: a job that requires secrets is refused when its signature was not verified

- A job whose secret list requires a secret (a proxy pool's credentials, an authenticated scan) is refused before it starts on a sensor that did not verify its signature, with rule `secrets_unverified` and the fix in the detail. Before, a proxy pool job failed later with "the job's signed secret list names none for it", which blamed the platform's list instead of the unverified job.

### Behaviour change: ports.allow is strict

- With `ports.allow` set, these are refused (rule `ports.allow`): a port scan that names no ports, a tool's top-N setting unless the job names a port list, a port list outside the allow-list in any settings layer or under any recognised port setting name, a port written with a sign or a leading zero, and a URL of a scheme with no known default port and no explicit port. See `docs/LOCAL_POLICY.md`.

### Changed: sdk-go v0.51.0

- The disk high watermark needs free space below both 15 % of the volume and 16 GiB (with the default budgets), so a sensor on a large volume no longer stops claiming with plenty of disk free.
- Certificate Transparency lookups are decoded one record at a time and refused `too_large` at the cap; a source cools down for at most 15 minutes after a 429.
- New setting `SENSOR_COMMAND_TYPES`: the only command types a sensor accepts.
- A command whose payload is over the 10 MiB poll limit is failed by its id instead of stopping all intake; a report that cannot be split below the platform's request limit is kept as a dead letter instead of retried in a loop.
- Late results of a run the platform took back carry the command and lease epoch they were made for.

### Fixed

- The reach probe and target guard tests no longer depend on the free space of the machine they run on.
