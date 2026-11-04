### Behaviour change: nuclei runs info templates when a scan sets no severity

- A nuclei scan without a `severity` setting now runs every severity, info included (technology detection, login panels, TLS and header posture, WAF detection). Before, the default was low to critical, so a scan of a well-kept host reported nothing at all. The platform files info matches as info exposures of the asset, not findings (openctem ingest); a scan or workflow step still narrows the severities with its `severity` setting.
- Upgrade the platform first: an older platform files the info matches as info findings.
