### Security: sensors verify the platform's signed jobs before they run them

- The sensor is built with an sdk-go that verifies the job signer's signature on every command right after its claim, before the local policy, the command gate and the tool (api RFC-040 §5.6). A command with a bad signature, or one that arrives unsigned while signed jobs are required, is failed with refusal rule `job_signature` and never runs.
- Pairing pins the signer keys the platform's hello lists (`identity.json` `job_signing_keys`). A sensor paired with a platform that signs jobs requires signed jobs.
- New settings: `SENSOR_JOB_SIGNING_KEYS` (key ids or base64 Ed25519 keys) and `SENSOR_REQUIRE_SIGNED_JOBS`. See "Signed jobs" in the README.
- Posture reports `jobs.signed`.
- **Upgrade note:** sensors paired earlier are unchanged. To require signed jobs on one, set `SENSOR_JOB_SIGNING_KEYS` to the signer's key id (`openctem-signer pubkey`) and `SENSOR_REQUIRE_SIGNED_JOBS=true`, or pair it again. Keep `<state dir>/job-signing-seq.json` on the persistent state volume.
