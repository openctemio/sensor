### Added: Certificate Transparency lookups for the platform (lookup.ct@1)

- A shared (platform) sensor with a pinned job-signing key now answers the platform's CT lookups and reports `lookup.ct@1`, in every profile (passive, standard, full, browser): for one organization's root domain per signed lookup job, the certificates crt.sh (then Cert Spotter) list, with per-source pacing, Retry-After, a body cap and a 20-hour per-organization answer cache. A source failure is reported as source status, never a failed job. The platform makes no CT request itself and turns CT monitoring on only when such a sensor is connected.
- New settings: `SENSOR_CT_LOOKUP` (`auto`, `0`, `1`), `SENSOR_CT_CRTSH_URL`, `SENSOR_CT_CERTSPOTTER_URL` (https, or `off`), `SENSOR_CT_CERTSPOTTER_KEY` / `SENSOR_CT_CERTSPOTTER_KEY_FILE`.
- An organization's sensor never serves them.
