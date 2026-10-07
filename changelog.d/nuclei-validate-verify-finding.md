### Changed: the nuclei finding check declares verify.finding@1

- The nuclei finding check (`nuclei-validate`, descriptor 1.1.0) now implements `verify.finding@1` in retest mode, and no longer reports the old capability words (`validation`, `vulnerability_scanning`).
- It takes no `mode` param, so a job asking for another mode is refused.
- How it runs, and every field of its result (matched_at, matcher_name, severity, response excerpt, template digest, evidence items), is unchanged.
- Folding it into nuclei waits for the platform to route `verify.finding` (research/62).
