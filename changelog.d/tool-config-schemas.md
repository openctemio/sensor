### Added: settings for subfinder, dnsx, httpx, katana, codeql, trivy and betterleaks, mapped from the capability params

- Seven tools gain a settings schema in their descriptor (`tool.yaml`), each applied to one fixed flag or field. The capability standard params map onto them:
  - subfinder (`discover.subdomains@1`):
    - `sources` → `-sources`;
    - `recursive` → `-recursive`;
    - `max_results` keeps at most N names per root domain.
  - dnsx (`resolve.dns@1`):
    - `record_types` → `-a`, `-aaaa`, `-cname`, `-mx`, `-ns`, `-txt`;
    - `wildcard_filter` → `-auto-wildcard`.
  - httpx (`probe.http@1`):
    - `ports` → `-ports`;
    - `follow_redirects` → `-follow-host-redirects` (same host only);
    - `tech_detect` → `-tech-detect`;
    - `tls_grab` → `-tls-grab`.
  - katana (`crawl.web@1`):
    - `depth` → `-depth`;
    - `js_parse` → `-js-crawl`;
    - `max_urls` keeps at most N URLs per start URL.
  - codeql (`sast.code@1`): `languages`, exactly one, → `--language`.
  - trivy:
    - `dev_deps` (`sca.deps@1`) → `--include-dev-deps`;
    - `os_pkgs` (`container.image@1`) → `--pkg-types os,library` or `library`;
    - `frameworks` (`iac.misconfig@1`) → `--misconfig-scanners`.
  - betterleaks (`secrets.code@1`): `history` → `betterleaks git` instead of `betterleaks dir`. This needs the `.git` directory in the scan root, and a scan without it fails rather than reporting nothing.
- semgrep `languages` is not mapped: semgrep cannot restrict a rule-config scan to one language (`--lang` works only with `-e`). A job that sets it fails instead of running every language.

### Security

- Each schema lives only in the tool's descriptor, so the schema the platform validates against and the one the sensor applies cannot drift.
- Values come from closed sets or tight patterns, so none can become a flag:
  - source names are letters and digits;
  - record types, codeql languages and trivy frameworks are enums;
  - ports are digits, `-` and `,`.
- The sensor checks each value again before mapping it, and refuses settings resolved against another schema.
- A capability param that a tool cannot honor still fails the job: nothing is dropped silently.
