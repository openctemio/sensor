### Security: signer keys rotate through an offline root; custom templates are trusted through the signed job

- The sensor is built with an sdk-go that can pin the installation's offline job-signing root (api RFC-040 P1.5). Pairing pins the root of the key set the platform serves, or the network owner sets the new `SENSOR_JOB_SIGNING_ROOT`. Job signatures are then accepted only from keys in the current root-signed key set, which is versioned, expires within 30 days and cannot be rolled back (`<state dir>/job-signing-keyset.json`). Signer keys rotate or are revoked without pairing again. With a root pinned and no valid key set, signed jobs are refused with rule `job_keyset`.
- The signed job now lists the SHA-256 of every custom template it carries. The platform's signer lists only templates approved in its scope ledger (api RFC-040 P2). A sensor that verifies signed jobs runs such templates without `SENSOR_TEMPLATE_SIGNING_KEYS`. That setting is now only a fallback for sensors without signed jobs, planned for removal. The local `allow_custom_templates` gate still applies.
- See "Signed jobs" and "Nuclei template trust" in the README.

### Upgrade notes

- A sensor with a root pinned needs the platform to keep a current key set deployed. An expired key set makes it refuse every signed job until a new one is served. Keep `<state dir>/job-signing-keyset.json` on the persistent state volume.
- A sensor on an older release that verifies signed jobs refuses statements that list templates, so jobs with custom templates fail on it until it is upgraded.
