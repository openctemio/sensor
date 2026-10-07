### Changed: nuclei, semgrep, trivy and betterleaks output is read by ctis/importer

The sensor now reads the native output of these four scanners with `ctis/importer`: the same parsers every OpenCTEM component uses, fuzzed, size- and depth-limited, with a field mapping spec per format. The sensor adds only what it alone knows:
- the asset the scan ran on (the target, the repository it checked out, or the CI job's repository);
- the branch context;
- relative paths under the scan root;
- for nuclei, the template provenance it annotates each result with (`template_digest`, `template_path`).

Differences from the previous parsers:

- **Severity**
  - semgrep maps `ERROR` to high and `INFO` to low (was critical and info).
  - betterleaks rates AWS and GitHub keys critical.
- **Titles**
  - semgrep findings are titled with the rule's message.
  - betterleaks titles name the rule.
  - trivy vulnerability titles no longer repeat the CVE id.
- **Secrets**
  - Secret types use the CTIS vocabulary (`aws_key`, `generic_secret`, ...).
  - Masked values keep the first 4 characters of a value of 16 or more.
  - Secret findings have confidence 85.
- **Finding identities**
  - The fingerprints of trivy and nuclei findings are those of `ctis/fingerprint`.
  - nuclei findings are filed on the host they matched, not on the address the result resolved to, and an `http://...` value is no longer stored as a domain.
  - **The first scan after the upgrade reports these findings under new identities.**
- **Corrected output**
  - A nuclei result the old parser dropped is now reported.
  - trivy no longer invents a PURL (`pkg:deb/...`) for packages whose output names none, and no longer uses the image name as a file path.
- **Behaviour**
  - Templates tagged `misconfig` are reported as vulnerabilities, as nuclei classifies them.
  - A nuclei result that names no host is skipped; output in which no result is usable fails the command.

### Removed

- The sensor's own converters: `internal/scanners/{nuclei,semgrep,trivy,betterleaks}/parser.go` and `nuclei/report_parser.go` (about 1,700 lines with their tests).
- The raw-output decoders the scanners use for their own status (`ParseJSONBytes`, the nuclei validation result lines) stay.

### Security

- Hostile scanner output is parsed by one fuzzed library with input, depth, record and text limits, instead of four hand-written converters.
- Credentials a nuclei match carries are masked in every field of the finding and of its asset: user info in a URL, and sensitive query parameter values such as `?api_key=`.
- Request and response bodies are not read.
- Raw secret values reach no field of a report. Tests assert this for betterleaks, trivy and nuclei.
- A code report the sensor cannot file on a repository is refused (`ErrNoAssetForFindings`). It is never filed on a placeholder asset.
