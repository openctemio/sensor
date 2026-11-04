### Fixed: nuclei honours a job's exclusions

- A step's `exclude` list reached nuclei as `-exclude`, a flag nuclei v3 does not define: in process the run aborted, and out of process (the default) the exclusions were dropped and the excluded hosts were scanned. Exclusions now reach nuclei as `-exclude-hosts`, which also stops redirects and template requests to them.
- Each exclusion is made exact: an IP address or CIDR range as is, a host name or the host of a URL as that host only, `*.example.com` as any subdomain of example.com. A value that names no host (for example a path) fails the scan with the reason instead of being ignored.
- Out of process, a resolved `retries: 0` setting and the settings' rate, concurrency and bulk size now reach nuclei as resolved (the child had fallen back to the command's raw limits and nuclei's default retry).
- Removed the never-set headless timeout and proxy credential options, whose flags nuclei v3 does not define, and the `proxy_auth` credential of the nuclei descriptor.

### Added: nuclei response size settings

- `response_read_kb` (sensor-level, 64 to 65536 KiB, default 10240) bounds how much of each response nuclei reads and matches on; `response_save_kb` (scan-level, 16 to 1024 KiB, default 1024, never above the read limit) bounds the response kept as a finding's evidence. Both appear in the console's tool settings forms. The defaults are nuclei's own, so results do not change until they are lowered.
- nuclei no longer writes a base64 copy of each template into its results (`-omit-template`); nothing read it.
