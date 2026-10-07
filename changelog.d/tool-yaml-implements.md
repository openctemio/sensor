### Added: every built-in tool is described by an embedded tool.yaml that names its capabilities

- **Descriptors.** The 11 built-in tools (subfinder, dnsx, naabu, httpx, katana, nuclei, nuclei-validate, semgrep, codeql, trivy, betterleaks) are each described by a `tool.yaml` embedded in the binary (OpenCTEM Tool Contract v1). The Go literals are gone.
  - Each descriptor names the capabilities the tool implements: `subfinder` → `discover.subdomains@1`, `dnsx` → `resolve.dns@1`, `naabu` → `scan.ports@1`, `httpx` → `probe.http@1`, `katana` → `crawl.web@1`, `nuclei` → `vuln.templates@1`, `semgrep` and `codeql` → `sast.code@1`, `trivy` → `sca.deps@1`, `container.image@1` and `iac.misconfig@1`, `betterleaks` → `secrets.code@1`.
  - Each descriptor also carries its engine, its presentation and its batch shape.
  - The adapter versions are now 2.0.0.
- **Single schema source.** naabu's and nuclei's settings schemas are read from their descriptors, so the schema scans are validated against and the contract cannot drift.
- **Capability jobs.** The sensor runs capability jobs (sdk-go `core.CapabilityScanner`):
  - the job's standard params are mapped onto the tool's settings by the descriptor (naabu: `ports`, `top_n` → `top_ports`, `rate`; nuclei: `severity`, `tags`, `exclude_tags`);
  - the job's tier ceiling is enforced;
  - the runtime checks the output against the capability's contract and stamps the capability in the provenance.
- **Manifest.** The sensor manifest reports each tool's full descriptor by digest, and the tool's capability ids next to its older capability words.
- `tools manifests` prints each tool's capabilities.

### Fixed

- dnsx no longer claims `host` targets, and katana no longer claims domain and host targets. The capabilities they implement do not take them, so the platform never sends them.

### Upgrade notes

- The sensor now pins sdk-go and ctis `main` (CTIS 1.5). Reports are stamped `"version": "1.5"`, with no new member: CTIS 1.4 receivers read them unchanged.
- The older capability words (`portscan`, `dast`, `validate:nuclei`, `retest:<tool>`, ...) are still reported, because the platform routes by them until it routes by capability ids. They will be removed then.

### Security

- An invalid descriptor compiled into the sensor stops it at start. Invalid means:
  - an unknown key;
  - a capability outside the taxonomy;
  - a tier below a capability's floor;
  - an input or output the capability does not allow.
- A capability job never runs with a setting the tool cannot honor. Each of these fails the job:
  - a param the descriptor does not map;
  - a value outside the capability or the tool's schema;
  - a param that contradicts the scan's own setting;
  - a tool above the job's tier ceiling.
- A scanner that is not on the contract fails a capability job instead of ignoring its params.
