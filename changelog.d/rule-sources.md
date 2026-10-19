### Added: rule sources (platform, organization or both in one run)

- Scans honor the job's rule sources (sdk-go `ScanOptions.RuleSources`): `both` (default), `platform` or `tenant`. The sensor reports `rule.sources@1`, so the platform sends tenant-only jobs to it.
- nuclei: `both` is now one run with the sensor's templates and the custom templates instead of two. With `-disable-unsigned-templates`, nuclei gets copies of the custom templates signed with a key made for that run only (certificate in `NUCLEI_USER_CERTIFICATE`), so it still loads only templates the sensor checked. `tenant` runs only the custom templates, still with dangerous types excluded.
- betterleaks: with `both` the organization's rules extend the sensor's config (or the default rules) instead of replacing them. A global allowlist, `[extend] useDefault = false` or `disabledRules` is refused in that mode. An `[extend]` path or url is always refused.
- opengrep and semgrep: `tenant` runs only the organization's rules.
- Findings of the organization's rules carry `tenant:`-prefixed rule ids (nuclei, betterleaks, opengrep, semgrep) and nuclei results carry `rule_source: tenant` and the digest of the template as received.

### Behaviour change: betterleaks custom rules no longer replace the default rules

- A scan with custom betterleaks rules now runs them together with the default (or configured) rules unless the platform asks for the organization's rules only. A custom config with a global allowlist must move it onto its own rules or run tenant-only.
