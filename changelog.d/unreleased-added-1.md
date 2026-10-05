### Added

- **Setup & health checklist on the platform** (api RFC-033, config report;
  OpenCTEM research/26). The daemon reports its preflight checks to a
  platform that lists the `config_report` feature (sdk-go config report):
  a tool that cannot run and why (missing or broken), a state directory
  that does not persist, scanners inheriting the proxy, an unreadable
  `SSL_CERT_FILE`, legacy names, and this sensor's own checks below. Only
  each setting's presence is reported, never a value. Every setting the
  sensor reads is declared, so an unknown `SENSOR_*` variable is named with
  a "did you mean" (`config.env_unknown`).
- **No more silent configuration mistakes.** An unknown key in the
  `-config` file (`max_job:` for `max_jobs:`), dropped silently before, is
  now a start-up warning with the key it was probably meant to be and a
  `config.file_unknown_key` check; a `${VAR}` whose variable is unset
  (expanded to an empty value) is a warning and a `config.file_unset_var`
  check; `-daemon` without `-enable-commands` (a daemon that never runs a
  platform scan) is a warning and `config.commands_disabled`; a retired
  scanner name (`gitleaks`) is `config.tool_retired`. The file still loads
  as before: none of these stops the sensor.

- httpx keeps what it learns about the server (api research/22 E5): the TLS
  leaf certificate (`-tls-grab`), the favicon hash (`-favicon`), the JARM
  fingerprint (`-jarm`) and the CDN/WAF in front (`-cdn`) are on by
  default and reach the platform. The certificate becomes a `certificate`
  asset linked from the HTTP service. `-asn` stays off by default: httpx
  looks ASNs up at ProjectDiscovery's API, which would send every scanned
  address to a third party.
