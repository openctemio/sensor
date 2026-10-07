# Changelog

All notable changes to the OpenCTEM agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline builds from a `v*` tag: `.github/workflows/release.yml`
runs GoReleaser to produce archives for linux/amd64, linux/arm64 and
darwin/arm64 with checksums, and `docker-publish.yml` builds the multi-arch
image. Both are gated on the tag — nothing is published without one.

Unreleased changes are kept one file per change in
[`changelog.d/`](changelog.d/README.md) and folded in here by the release
(Release Prepare).

## [Unreleased]

## [v0.11.0] — 2026-10-07

### Security

- Hostile scanner output is parsed by one fuzzed library with input, depth, record and text limits, instead of four hand-written converters.
- Credentials a nuclei match carries are masked in every field of the finding and of its asset: user info in a URL, and sensitive query parameter values such as `?api_key=`.
- Request and response bodies are not read.
- Raw secret values reach no field of a report. Tests assert this for betterleaks, trivy and nuclei.
- A code report the sensor cannot file on a repository is refused (`ErrNoAssetForFindings`). It is never filed on a placeholder asset.

- Each schema lives only in the tool's descriptor, so the schema the platform validates against and the one the sensor applies cannot drift.
- Values come from closed sets or tight patterns, so none can become a flag:
  - source names are letters and digits;
  - record types, codeql languages and trivy frameworks are enums;
  - ports are digits, `-` and `,`.
- The sensor checks each value again before mapping it, and refuses settings resolved against another schema.
- A capability param that a tool cannot honor still fails the job: nothing is dropped silently.

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

### Security: nuclei evidence is kept raw with credentials marked; retests prove a fix

- The sensor speaks CTIS 1.6.
- **Nuclei findings carry typed evidence.** Each finding carries the matched request and response, the curl command and the extracted values as `evidence_items`, raw, with every credential (Authorization, Cookie, Set-Cookie, credential query values) marked sensitive. The platform masks marked values for display and reveals them only to authorized users. Outside the evidence, no credential reaches the report: the web location (`finding.web.url`) keeps parameter names and drops every query value.
- **Retests and re-verification run nuclei with `-ms`.** A template that ran and did not match returns the attempt's HTTP exchange as the proof of the fix. A template whose requests failed is inconclusive, with an error class that never quotes the URL. Each verdict carries the `template_digest` of the template that ran.
- The re-verification run is never verbose: the raw request and response never reach the logs.
- katana reports CTIS 1.6 `endpoints` besides its `discovered_url` assets (descriptor 2.1.0 declares `endpoint`).

- nuclei masks Authorization and Cookie values itself (`***`) and cannot be told not to, so those two headers are never revealable on nuclei evidence; every other credential in the exchange arrives raw and marked.

### Security: katana keeps to the job's web scope

- A job can carry a web scope: hosts, path prefixes, deny paths and methods (sdk-go `pkg/webscope`). katana declares `features.web_scope` (descriptor 2.1.0) and maps the scope onto its flags:
  - each deny path becomes an out-of-scope regex (`-cos`) that matches it in any case and percent-encoded, with repeated slashes or a backslash;
  - path prefixes and hosts become an in-scope regex (`-cs`);
  - the crawl stays on the target's host (`-fs fqdn`) with redirects off;
  - form filling is off unless the scope allows POST.
- The results are filtered with the scope again before they are reported.
- A real katana crawl of a site that links to `/admin` and `/logout` (plain, dot segments, upper case, percent-encoded, a form and a script `fetch`) made no request to either. Without the scope, the same crawl requested both.
- A job with a web scope fails for a recon tool that cannot keep to one (every tool but katana), and an invalid scope fails the job. Neither runs without the scope.

### Security: a secret scanner's raw match no longer survives in the title or other fields

- The betterleaks and trivy parsers mask the raw secret, the match line and each secret-looking word of the match in every field of a secret finding. This covers the title, message, description, the `commit_message` property, tags and fingerprints, not only the snippet. Before, a rule description or a commit message that repeated the secret carried it to the platform.
- sdk-go is re-pinned: the tool runtime's output checks apply the same rule to every out-of-process tool, and the importers mask secrets in every field.

### Security: re-verify results no longer carry the credentials of the matched URL

- A nuclei re-verify (validate) result put the raw `matched-at` URL into its `MatchedAt` and its summary, which the platform shows as the retest reason. A credential in that URL, such as an `api_key` query value or user info, reached the platform. Both now use the redacted URL, as the evidence already did.

### Upgrade notes

- Nuclei findings move their URL from `location.path` to `finding.web.url`, and a URL's query values are dropped (names kept). Fingerprints of findings on URLs with user info, a query or a fragment change once.
- A retest `fixed` verdict needs the attempt's exchange (sdk-go). A nuclei retest whose run gave no exchange is `unverifiable` instead of `fixed`.

- The sensor now pins sdk-go and ctis `main` (CTIS 1.5). Reports are stamped `"version": "1.5"`, with no new member: CTIS 1.4 receivers read them unchanged.
- The older capability words (`portscan`, `dast`, `validate:nuclei`, `retest:<tool>`, ...) are still reported, because the platform routes by them until it routes by capability ids. They will be removed then.

### Behaviour change: `*.domain` in the local policy covers the domain itself

- A `targets.allow` or `targets.deny` entry `*.example.com` now covers `example.com` and every name below it. It used to cover only the names below. This is how the platform reads a scope pattern (api RFC-054 §4.1), so the sensor and the platform agree on what `*.example.com` means.
- To keep the apex out of an allow wildcard, add `example.com` to `targets.deny`. A deny wildcard now refuses the apex too.
- Entries and targets compare case-insensitively, without a trailing dot, in IDNA ASCII form.
- Needs sdk-go with the matching change (sdk-go #192).

### Behaviour change: one refused target no longer fails a scan job

- A scan target the local policy refuses, or cannot check, is skipped, and the job runs on its other targets. "Cannot check" means the name does not resolve or the target is a wildcard pattern. The job completes as partial and lists every skipped target with a reason: `unresolvable`, `wildcard_pattern`, `denied_by_policy` or `invalid_target`. The platform shows "Completed with N targets skipped".
- The job still fails, with the list, when every target is refused or when the single target of a single-target tool is refused. Retest and validation jobs are still refused whole.
- An address the policy cannot check is never scanned.
- The task log now shows the sensor's own lines: received, the policy check and each skipped target, the outcome, and a hand-back to the platform. A job refused before any tool started has a log saying why.
- `sensor policy explain` prints the per-target reason, for example `rule targets (unresolvable)`.

### Removed

- The sensor's own converters: `internal/scanners/{nuclei,semgrep,trivy,betterleaks}/parser.go` and `nuclei/report_parser.go` (about 1,700 lines with their tests).
- The raw-output decoders the scanners use for their own status (`ParseJSONBytes`, the nuclei validation result lines) stay.

### Removed: CI mode (moved to openctemio/ci)

- CI scanning moved to openctemio/ci: the `openctem-ci` binary, the
  `ghcr.io/openctemio/ci-<tool>` and `ghcr.io/openctemio/ci` images, the GitHub
  Action and reusable workflow, and the GitLab templates. They report with the
  CI job's OIDC identity and ask the OpenCTEM gate.
- Removed from the sensor: the CI run (OIDC exchange, central gate), the local
  gate (`-fail-on`), pull request comments (`-comments`), CI detection
  (`-auto-ci`), changed-files scans, SARIF output (`-output-format`), the
  `ci/` templates, the `ci` and `ci-cached` Dockerfile targets and the
  `sensor:*-ci` image, and `scripts/pin-ci-images.sh`. A one-shot run in a CI
  job prints where CI scanning went.
- The default (platform) image no longer carries semgrep, betterleaks or trivy
  (nuclei and the recon tools stay); a daemon that runs them uses the per-tool
  images `sensor:*-semgrep`, `*-trivy`, `*-betterleaks`.
- **Upgrade note:** pipelines that use `openctemio/sensor/ci/...` or
  `ghcr.io/openctemio/sensor:*-ci` move to openctemio/ci (`uses:
  openctemio/ci@v1`, or `include:` its GitLab templates) and replace the
  `API_KEY` secret with a CI trust configuration in OpenCTEM.

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

### Added: trivy builds software bills of materials (`sbom.generate@1`)

- trivy now implements the `sbom.generate@1` capability (descriptor version 2.1.0). An SBOM job lists every package of a repository or image (`--list-all-pkgs`) and runs only trivy's license scanner, so no vulnerability matching happens and no vulnerability database is needed. Packages are reported as CTIS dependencies with name and version.
- The `dev_deps` param includes development dependencies.
- Other trivy capabilities run as before. The platform routes `sbom.generate@1` once its catalog marks the capability as routed.

### Changed

- sdk-go is pinned to the commit with per-target admission (sdk-go #191).

### Changed: CI refuses openctemio dependencies pinned off main

- A new CI job fails when `go.mod` pins sdk-go or ctis to a commit that is not
  on that repository's `main` branch. A feature-branch pin breaks once the
  branch is squash-merged (the commit then exists on no branch), and a release
  built from it cannot be reproduced.

- Re-pins sdk-go from `3e8d221` (a branch commit of sdk-go #192, squashed on
  main as `3883b87`) to `3883b87`: the same change, now on main.

### Changed: the nuclei finding check declares verify.finding@1

- The nuclei finding check (`nuclei-validate`, descriptor 1.1.0) now implements `verify.finding@1` in retest mode, and no longer reports the old capability words (`validation`, `vulnerability_scanning`).
- It takes no `mode` param, so a job asking for another mode is refused.
- How it runs, and every field of its result (matched_at, matcher_name, severity, response excerpt, template digest, evidence items), is unchanged.
- Folding it into nuclei waits for the platform to route `verify.finding` (research/62).

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

### Fixed

- dnsx no longer claims `host` targets, and katana no longer claims domain and host targets. The capabilities they implement do not take them, so the platform never sends them.

### Fixed: tool and validation lines reach the command's log on the platform

- Every scanner ran on the sensor's own tool host, which had no log sink, so no tool line ever reached the platform: tasks showed an empty log.
- The host now ships through the SDK's command log (`kit.ToolLogSink`):
  - each tool's lines;
  - "Tool <name> <version> started";
  - "Tool <name> finished: <status>", with the exit code, records, duration and error class.

  This covers scans, retests and re-verifications. Lines are redacted (credentials in headers, secret-named parameters, URL user info), bounded per command and batched.
- Validate jobs write "Validation started" and "Validation finished: <outcome>" to the command's log.
- Together with the SDK's own received, admission, refusal and outcome lines, every command now has a readable log.

## [v0.10.0] — 2026-10-07

### Security: CI templates run the sensor image by digest; the GitHub action verifies its signature

- The GitHub and GitLab templates in `ci/` pin every sensor image to a release by digest (`ghcr.io/openctemio/sensor:v0.9.1-<variant>@sha256:...`) instead of the moving `latest-*` tags. Each digest's cosign signature (keyless, issued to this repository's release workflow) was verified when it was pinned.
- `scripts/pin-ci-images.sh vX.Y.Z` resolves, verifies and re-pins the templates for a new release; it refuses a digest whose signature does not verify.
- The composite action (`ci/github/action.yml`) resolves `version` to a digest, verifies its signature (`verify_signature`, default on) and runs exactly that digest. Its `version` default is now a release tag instead of `latest`.
- `ci/README.md` documents verification with cosign v3 and how to enforce the gate (the templates start in rollout mode).

### Security: every task of a ported tool is admitted against the local policy

- Before a ported tool's child starts (httpx, nuclei, subfinder, dnsx, naabu,
  katana, trivy, semgrep and the next ports), the task is admitted against
  the sensor-local policy in force at that moment: the kill switch,
  `tools.allow` (by the tool's name or the name it is configured under, such
  as `trivy-fs`), every target against the target guard, and the run time
  cap. A refused target is removed from the task, so the tool never sees or
  reaches it, and the report lists it under `refused_targets`
  (`refused_by_policy`); a task with no target left fails. A `SIGHUP` reload
  applies to the next task.
- Tasks carry the mode the sensor runs in (daemon, or runner for a CI run).
- sdk-go is pinned to its current main (per-task admission in the tool
  runtime).

### Upgrade notes

- If you copied a template, replace its `latest-*` image references with the pinned digests, or run `scripts/pin-ci-images.sh` on your copy.

- A local policy that lists `checks.allow` must add `retest` for the sensor to accept retests (see `docs/sensor-policy.example.yaml`).

- Run an OpenCTEM API that serves sensor protocol v2 (every API since
  2026-10-02; the API removed protocol v1). Upgrade the API first if it is
  older.
- `SENSOR_PROTOCOL=v1`, `-protocol v1` and `server.protocol: v1` are refused at
  start-up: remove the setting (`auto` and `v2` are the same).

### Behaviour change

- A server-controlled daemon without `API_KEY` no longer exits with code 2:
  it pairs. Without `API_URL` it still exits with code 2.

### Behaviour change: the local policy admits each re-verification

- The re-verify target is admitted against the sensor-local policy in force
  before nuclei starts (kill switch, target rules), like every ported tool.
- `tools.allow` admits `nuclei-validate` exactly when it admits nuclei (by
  name, by the name nuclei is configured under, or by `nuclei-validate`). A
  policy whose `tools.allow` leaves nuclei out now refuses re-verifications.

### Removed: sensor protocol v1

- The sensor speaks protocol v2 only (sdk-go without the v1 fallback client).
  Against a platform that does not serve protocol v2 every call fails with
  "the platform does not serve sensor protocol v2" instead of falling back to
  the retired `/api/v1/agent/*` routes.

### Removed: the unused CodeQL SARIF parser

- `internal/scanners/codeql` no longer has its own SARIF parser (`Parser`, `ParseToCTIS` and the SARIF types): nothing called it, CodeQL output already went through the SDK SARIF parser. `assetctx.SARIFProvenance`, used only by it, is removed too.

### Deprecated: API keys in CI

- A one-shot run in CI with `API_KEY` and no OIDC identity prints a
  deprecation warning.

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

### Added: CI jobs authenticate with their OIDC identity and follow the platform's gate (api RFC-051)

- With `-push` in a GitHub Actions job allowed `id-token: write`, or a GitLab
  CI job with an `id_tokens` variable (`OPENCTEM_ID_TOKEN`), and
  `OPENCTEM_TENANT_ID` set, the one-shot run exchanges the job's OIDC token
  for a run token (at most 15 minutes, one repository) instead of using
  `API_KEY`. No token is printed.
- After the scans it asks the platform's gate for the verdict, prints the
  blocking findings (file:line) and the run link, and exits 1 on `fail`.
  `-fail-on` only decides when the platform cannot be reached; without it an
  unreachable gate exits 2.
- Pull request runs compare findings with the default branch through the run
  (repository and base branch decided by the platform).
- CI templates (`ci/github`, `ci/gitlab`) grant or request the job's token and
  take the organization id; push no longer turns off without `API_KEY` when
  `OPENCTEM_TENANT_ID` is set.

### Added: every scanner runs in a sandbox

The daemon confines each tool run (sdk-go `pkg/sensorkit/executor`): a private
throwaway directory, resource limits (memory, processes, file size, open
files), no_new_privs, Landlock (writes only in its directory and the paths its
wrapper declares; no read of the sensor's credentials file, outbox and key,
local policy, `-config` file, Tenable.sc connector configuration), a seccomp
filter, and a non-dumpable sensor. `SENSOR_SANDBOX=auto` (default for the
daemon), `required`, `off`; one-shot runs sandbox only when it is set. Each
scanner declares what it writes (its report directory, nuclei's private
configuration, the CodeQL database). Checked with every bundled scanner in
the image: the same templates, assets and findings with the sandbox off and
required.

### Added: httpx and nuclei run out of process, on the tool contract

httpx and nuclei are ported to the tool contract (sdk-go `pkg/tool`,
docs/rfcs/sensor-sdk-v2.md). Each scan re-executes the sensor as
`openctemio-sensor __openctem-tool <name>` inside the task sandbox; the tool
runs there and speaks adapter protocol v1 to the sensor, which checks every
record again (CTIS validity, the tool's declared output types, record and
byte limits, control characters) and stamps the provenance
(`metadata.properties.provenance`: tool, adapter version, manifest digest,
sandbox status, task). The CTIS output is the same as before (golden tests
compare both paths). nuclei's interactsh token and proxy credentials reach
the tool as declared credentials only. The manifests are compiled into the
binary and reported to the platform by digest (`tools[].contract`);
`openctemio-sensor tools manifests [--json]` prints them.
`SENSOR_TOOL_RUNTIME=in-process` runs both tools in the sensor's process as
before (rollback switch).

### Added: local policy commands, SIGHUP reload, schema v2

- `openctemio-sensor policy validate|digest|explain|install`: check a policy
  with the sensor's own loader, print the digest the sensor reports, ask
  whether a job would be admitted and by which rule it is refused, and
  install a reviewed file (`--expect-sha256`, refused on a mismatch, an
  invalid policy, a symlink destination or a directory anyone can write;
  atomic 0644 write; `-pid` sends SIGHUP). Local files only.
- SIGHUP reloads the local policy (owner decision D10). A file that does not
  load engages the kill switch until a later reload loads a valid one; the
  sensor never keeps the previous policy silently. The validating executor
  and the Tenable.sc scan executor follow the reload.
- Local policy schema v2 (sdk-go): every v1 key plus `managed.accept`; v1 is
  frozen (owner decision D13). The sensor reports the schemas it reads.
- The absent-policy warning says what actually happens: jobs may enable
  out-of-band callbacks, and custom templates run only when
  `SENSOR_TEMPLATE_SIGNING_KEYS` is set.

### Added: the platform's retests of nuclei findings

- The sensor serves the platform's `retest` command for nuclei findings and advertises `retest:nuclei` (with `validate:nuclei`). In its sandboxed child, the `nuclei-validate` tool first checks each address with a TCP connect, then re-runs each finding's own template with the re-verification's safety flags (one signed template, destructive classes excluded, rate ceiling). A finding whose template matches again is `still_present`. One whose template ran against the reachable address and did not match is `fixed`. Anything else (an unreachable address, a template that is not installed or is excluded, a nuclei error) is `unverifiable`, never `fixed`. The platform closes or reopens findings from these verdicts.
- Every address passes the local policy (as for a scan) and the validate guard (no loopback, link-local or cloud-metadata target) before nuclei runs.

### Added: run one job and exit (-job, SENSOR_JOB_ID)

- `-job <command id>` (or `SENSOR_JOB_ID`) runs the one platform command with that id and exits: one sensor pod per job (Kubernetes Job). It implies `-daemon -enable-commands`, sets up as a daemon does, claims the command by id, runs it with every check a polled command gets, waits for its results to be delivered, and exits 0. It exits non-zero when the claim is refused, the job is not run (it is released for another sensor), or results are not delivered in time. Mount the outbox on a persistent volume for such pods.

### Added: pair the sensor instead of pasting an API key (api RFC-052)

- `openctemio-sensor pair [CODE]`: the sensor creates its own Ed25519 key
  (`<state dir>/identity/`, 0600 files in a 0700 directory) and prints a code
  and a fingerprint; an administrator compares the fingerprint and approves
  it under Sensors > Pair a sensor. With a code from "Expect a sensor" it
  attaches to that code instead. `pair -repair` replaces a lost or
  compromised key.
- A daemon started without `API_KEY` pairs on first start, then signs every
  request with its key. `SENSOR_CA_FINGERPRINT` and `SENSOR_PLATFORM_KEY`
  from the install snippet pin the platform at first contact (`API_URL` must
  then use a host name).

### Added: betterleaks and codeql run out of process, on the tool contract

- Dispatched betterleaks scans and codeql scans run in the task sandbox as
  `openctemio-sensor __openctem-tool <name>`, like trivy and semgrep: the
  report comes back as a checked artifact and the sensor parses it with the
  scan's asset, branch and commit as before (parity tests compare both
  paths). betterleaks declares no network at all.
- A configured CodeQL database path is resolved by the sensor and is the
  child's only extra write path.
- Both manifests are listed by `openctemio-sensor tools manifests [--json]`.

### Added: naabu and katana run out of process, on the tool contract

- naabu and katana join httpx, subfinder and dnsx: each scan runs in the
  task sandbox as `openctemio-sensor __openctem-tool <name>`, and the sensor
  checks and stamps every record. The CTIS output is unchanged (golden
  parity tests compare both paths).
- naabu runs as a TCP connect scan and declares no Linux capabilities (the
  sandbox grants none). A scan configured as a SYN scan, which needs raw
  sockets, stays in the sensor process as before. A scan's naabu settings
  (ports, rate, retries) are applied by the sensor before the child starts.
- Both manifests are listed by `openctemio-sensor tools manifests [--json]`.

### Added: nuclei re-verification runs out of process, on the tool contract

- A `validate` command that re-runs a finding's nuclei template runs in the
  task sandbox as `openctemio-sensor __openctem-tool nuclei-validate`, with the
  same safety flags as before (one signed template, one target, destructive
  tag classes excluded, rate ceiling). Outcomes, summaries, template digests
  and evidence are unchanged (parity tests compare both paths).
- `SENSOR_TOOL_RUNTIME=in-process` runs it in the sensor process again.
- The manifest is listed by `openctemio-sensor tools manifests [--json]`.

### Added: subfinder and dnsx run out of process, on the tool contract

- subfinder and dnsx are ported to the tool contract like httpx: each scan
  re-executes the sensor as `openctemio-sensor __openctem-tool <name>` in the
  task sandbox, and the sensor checks and stamps every record (declared
  output types, limits, provenance). The CTIS output is unchanged (golden
  parity tests compare both paths).
- The sensor reads its DNS resolvers (`SENSOR_DNS_RESOLVERS` or
  `/etc/resolv.conf`) and hands them to the child, so the tools still never
  use their built-in public resolver lists.
- Both manifests are compiled in and listed by
  `openctemio-sensor tools manifests [--json]`; `SENSOR_TOOL_RUNTIME=in-process`
  still runs them in the sensor process (rollback switch).
- Each ported tool now registers itself in its own package, so porting the
  next tool touches only that package.

### Added: trivy and semgrep run out of process, on the tool contract

- Each trivy and semgrep scan runs in the task sandbox as
  `openctemio-sensor __openctem-tool <name>`. The scanner's report comes back
  as a checked artifact (confined to the task directory, size and digest
  verified) and the sensor parses it with the scan's asset, branch and commit
  exactly as before, so the findings are unchanged (parity tests compare both
  paths).
- A report larger than 64 MiB now fails the scan instead of being ingested;
  `SENSOR_TOOL_RUNTIME=in-process` restores the previous path.
- Registry credentials (`TRIVY_USERNAME` / `TRIVY_PASSWORD`) and `SEMGREP_*`
  settings still reach the tools only through the scanner environment, never
  through the task.
- trivy reports list their capabilities in a stable order.
- Both manifests are listed by `openctemio-sensor tools manifests [--json]`.

### Changed

- httpx follows redirects on the same host only (`-follow-host-redirects`).
  It used to follow any redirect, so a scanned host could point the probe
  at another host.
- katana crawls the target host only (`-fs fqdn`, was `rdn`: every host
  under the registrable domain), and URLs on any other host are dropped
  from its results.

### Changed: built with sdk-go v0.18.0

- The sensor now pins the released sdk-go v0.18.0 (tool builder, retest
  command, per-command logs, run one job, SARIF through the ctis importer)
  instead of a pre-release commit.

### Changed: SARIF results convert through the ctis importer

- SARIF written by a scanner without its own parser (CodeQL in one-shot mode) and by tools on the tool contract (`output.format: sarif`) converts with the SDK's `core.SARIFParser`, which now runs on the ctis importer, the conversion the platform uses. The findings, their asset and the report branch are unchanged; the input gets the importer's hostile-input limits, and a user and password in a SARIF `versionControlProvenance` URL no longer reach the asset.

### Changed: built against the sdk-go importer release candidate

- The sensor builds against sdk-go `main` with `pkg/importtool` (the file importer as a parser-class tool) and the tool adapters running on `ctis/importer`. The sensor does not register the import tool yet: no runtime delivers task input files, so a registered parser would be inert.

### Fixed

- Recon tools (subfinder, dnsx, naabu, httpx, katana) run at the scan's
  rate limit (the command's `rate_limit`, capped by the local policy's
  `rate.max_rps`). It was dropped and every run went at the tool's default.

### Fixed: pin sdk-go v0.18.0

- go.mod pointed at an sdk-go branch commit that is not on sdk-go main (the SARIF importer change, squash-merged as sdk-go #187). It now requires the released sdk-go v0.18.0, which contains that change; behaviour is unchanged.

### Fixed: recon stays on the target's host and backs off when throttled

- katana runs with `-dr` (no redirects). Measured on katana v1.7.0 against
  two scratch hosts: with `-fs fqdn` alone, an in-scope link that redirected
  to the second host was still fetched there; filtering the results
  afterwards does not undo the request. In-scope links are still crawled.
- A scan's `rate_limit` and `concurrency` (capped by the local policy's
  `rate.max_rps`) only lower a recon tool's own limits: a scan asking for
  more than the tool's default no longer raises it, and `concurrency` now
  reaches the tool (`-threads` / `-c` / `-t`).
- A target answering 429 or 503 halves the rate of the job's later targets
  (down to 1 request/s) and waits 2 s, then 4 s, up to 30 s before the next
  one. The report says so: `target_throttled: true`, `throttled_targets`,
  `throttled_rate_limit`. No rotation or evasion.
- Extra args that would send a recon tool to other hosts are refused:
  `-fr`/`-follow-redirects`, `-fs`/`-field-scope`, `-cs`/`-crawl-scope`,
  `-ns`/`-no-scope`, `-dr`/`-disable-redirects` (any spelling).

## [v0.9.1] — 2026-10-05

### Fixed: dnsx, naabu and subfinder resolved through public resolvers; dnsx "completed, 0 records"

- dnsx, naabu and subfinder now run with `-r` set to the sensor's resolvers:
  `SENSOR_DNS_RESOLVERS` (new, IP or IP:port only), else the nameservers of
  `/etc/resolv.conf`. Before, dnsx and subfinder asked their built-in public
  resolvers (Cloudflare, Google, …) first, so every enumerated name went to
  a third party and names only the sensor's network knows did not resolve
  (research/22c B5). naabu already passed `-sr` (v0.9.0) and now gets the
  same list.
- A dnsx run that resolves none of its hosts fails, naming the resolvers
  (`dnsx resolved none of the N host(s) through resolvers …`), instead of
  completing with 0 records. A job whose targets all fail is failed; one
  where some resolve completes and lists the others in `failed_targets`.

### Fixed: nuclei scans ran default-login and intrusive templates

A scan passed no `-etags`, so a default nuclei scan of a customer's host ran
the template set's default-login (credential guessing) and `intrusive`
templates; only managed template sets had the release's `.nuclei-ignore`
(`dos`, `fuzz`, `bruteforce`, …), and a scan could select `default-login` or
`bruteforce` in its `tags` setting (api RFC-036 T1, research/22 S7).

- Every nuclei run now passes `-etags` with `intrusive`, `default-login`,
  `dos`, `fuzz`, `fuzzing`, `bruteforce`, `brute-force`, `local` and
  `txt-service`, plus the operator's and the scan's own exclusions: the
  sensor's own templates and custom templates, with or without managed
  content. Measured on nuclei v3.11.1, `-etags` drops a template however it
  was selected (directory, explicit `-t` file, `-id`, `-tags`).
- A scan whose `tags` setting names one of these classes fails with the
  reason (before: only `dos`, `fuzz`, `fuzzing`, `intrusive` were refused).
- `-itags` / `-include-tags`, which re-admit an excluded template, are
  refused in extra args.
- Re-verifications (`validate`) exclude `default-login` too.
- The `NewDAST` preset no longer selects `default-login`.
- `-disable-update-check` and `-disable-unsigned-templates` are unchanged.

There is no intrusive mode: it needs an approved, owner-ceilinged grant on
the command (RFC-036 T2), which does not exist yet.

## [v0.9.0] — 2026-10-04

### Fixed: nuclei ran without 262 templates, its release's exclusion list and its version

Every scan of the managed nuclei-templates set (v0.8.0, nuclei v3.11.1,
templates v10.4.9) logged `Could not read nuclei-ignore file` twice,
`Found 262 templates with runtime error` and `nuclei-templates version:
(unknown)`.

- **Root cause.** nuclei reads its templates directory, the release version
  and `.nuclei-ignore` from its own configuration directory, not from `-t`.
  The managed set was passed with `-t` from outside nuclei's configured
  directory, so nuclei refused every helper file the templates load
  ("access to helper file ... denied"; 261 payload wordlists and 1 helper in
  a pre-condition) and never ran those templates; the release's
  `.nuclei-ignore` was never installed, so the denial-of-service, fuzzing and
  brute-force templates it excludes ran by default.
- **Fix.** Each nuclei run over a managed set gets a private configuration
  directory (`XDG_CONFIG_HOME`, 0700, removed after the run) naming the set
  and its release, with the release's `.nuclei-ignore` plus the baseline
  tags `dos`, `local`, `fuzz`, `bruteforce`, `txt-service` (always excluded,
  even if a release drops one). The ignore file is read only as a regular,
  bounded file; entries outside the set are dropped. Re-verifications and
  the refresh check use the same configuration.
- **Coverage of a default scan** (critical/high/medium/low, signed only):
  7052 templates before, 7036 after: 18 restored (8 critical, 6 high,
  4 medium; the other 244 of the 262 are info-level technology detections
  that run when a scan includes info), 34 now excluded by the release's own
  list (23 fuzz, 7 dos, 1 bruteforce, 3 weak-matcher files). 0 runtime
  errors, 0 `[ERR]` lines.
- **Refresh gate.** A downloaded release must pass `nuclei -validate`
  (signed templates) for all but `SENSOR_CONTENT_NUCLEI_MAX_TEMPLATE_ERRORS`
  (default 10) templates, or it is refused and the current set stays.
- **A forced refresh of the installed content is no rollback** whatever
  dates the two copies carry.
- **No update checks at scan time.** Every nuclei scan runs with
  `-disable-update-check`, managed set or not (one-shot runs without managed
  content used to let nuclei check for and download templates).

### Added: a pinned, gated nuclei-templates release in the images; template digests on findings

- The `default`, `full` and `nuclei` images bake nuclei-templates v10.4.9,
  pinned with its archive SHA-256 and gated at build by
  `scripts/nuclei-templates-bake.sh` (validation with the pinned nuclei
  against `docker/nuclei-templates-allowlist.txt`, a scan run with the
  sensor's flags, the release's exclusion list). The `nuclei` image no longer
  runs `nuclei -update-templates` (an unpinned download) at build. The
  templates are root-owned and read-only to the sensor. CI checks that both
  Dockerfiles pin the same release, and the image smoke test checks the
  baked set as shipped.
- The sensor adopts the baked set as its managed content with its release,
  archive digest and release date (`openctem-templates-release.json`), so
  heartbeats and results name it from the first scan.
- Findings carry `template_digest` (`sha256:` of the template file that
  matched, read only inside the run's template directories) and
  `template_path`. Nuclei re-verifications report `template_digest`,
  `templates_version` and `templates_digest` in their evidence (api
  research 18, owner decision O6: a different digest makes a retest
  inconclusive).

### Added: Tenable.sc connector (api RFC-047)

- **Pull from Tenable.sc, keys stay on the sensor.** `connector_sync`
  commands read hosts, open and mitigated vulnerabilities (`/rest/analysis`
  `vulndetails`, incremental `lastSeen`/`lastMitigated` windows) and plugin
  metadata, and push them as CTIS reports (tool `tenable_sc`, coverage
  `incremental`, at most 2000 findings each) bound to the command. The
  sensor reports the tool `tenable_sc` when the connector is configured.
- **Owner-written config, fail closed.** `-tenable-sc-config`,
  `SENSOR_TENABLE_SC_CONFIG` or `/etc/openctem/connectors/tenable-sc.yaml`
  (or the `TENABLE_SC_*` shorthand) holds the URL, key files, CA file or SPKI
  pins and an allow-list of operations and repositories the platform cannot
  widen. No skip-verify option; redirects refused; loopback, link-local and
  metadata addresses refused; caps on response size, records, fields and
  request rate. See `docs/TENABLE_SC.md`.
- **Scan launch from OpenCTEM.** `connector_scan` commands create, launch and
  poll one Tenable.sc scan on checked targets with an allowed policy,
  repository and zone, push its results (coverage `full` only for a completed
  and imported scan, else `partial`) and delete the scan definition they
  created. Targets are refused unless they are single IPs, narrow ranges or
  host names outside loopback, link-local and metadata, within
  `max_targets_per_scan` and the sensor-local policy. Registered only when an
  instance allows `scan`.
- **Catalog for the platform.** `connector_sync` reports the repositories,
  scan repositories, policies and zones the owner allowed (ids and names).

### Security: sensor-local policy (api RFC-040 §5.7)

- **The network owner's policy is the last word.** A read-only file
  (`-local-policy`, `SENSOR_LOCAL_POLICY`, default
  `/etc/openctem/sensor-policy.yaml` when it exists) sets the targets
  (CIDRs, IPs, names, `*.domain`, allow and deny), private ranges, ports
  (named in targets or in a job's `ports` setting),
  tools, job types, custom templates, interactsh, rate, maximum run time and
  a kill switch. Every job is checked after the claim and before any tool
  runs (sdk-go `LocalPolicy.AdmitCommand`). Host names are resolved and
  every address must pass. A refused job is reported failed with
  `refused by local policy: <rule>: <detail>`. Nothing the platform sends
  widens the policy. Template and docs for the install dialog:
  `docs/sensor-policy.example.yaml`, `docs/LOCAL_POLICY.md`.
- **Fail closed.** A policy with an unknown key or a malformed entry, an
  empty or world-writable policy, or a configured path that does not exist
  stops the sensor (exit code 2).
- **Validate jobs too.** The safe-check connects only through the policy's
  guarded dialer: it dials the checked addresses and never resolves the name
  a second time. A nuclei re-verification runs at most at `rate.max_rps`.
- **Kill switch.** While `kill_switch_file` (or `SENSOR_KILL_SWITCH_FILE`)
  exists, the sensor claims nothing and stops running jobs. Heartbeats
  continue with the message "paused by local policy".
- **No policy, no change** (owner decision Q3 (a)): the sensor works as
  before, logs warnings and reports `local_policy: absent` to a platform that
  reads it. Custom templates and interactsh stay allowed there, with a
  warning (Q4 (a)). In a policy they are off unless it turns them on.
- `timeout_seconds` of a scan is capped at 24h.
- sdk-go pinned to the main commit with the local policy
  (openctemio/sdk-go#140, a pseudo-version until the next sdk-go tag).

### Fixed

- **A nuclei re-verify that did not run its template is inconclusive, never
  "not detected"** (#124). With nuclei 3.x the "is it installed" check
  counted the `Listing available nuclei templates for <dir>` header and said
  yes for every id, and a run whose selection kept no template (tagged
  `intrusive`/`dos`/`fuzz`/`brute-force`, unsigned, or missing) exits 1 with
  `no templates provided for scan`, which was read as "ran, no match". A
  retest could then close a live finding as fixed. The check now lists with
  the same `-etags` as the run and counts only template files; a non-zero
  exit or that message is inconclusive (no state change on the platform).
  Confirmed with the real nuclei 3.11.1.
- **semgrep: a partially parsed file no longer drops every finding** (#122).
  semgrep writes `errors[].type` as an array (`["PartialParsing", [...]]`)
  when a file only partially parses; the parser expected a string, so the
  whole document failed to parse and the scan reported nothing.
- **dnsx falls back to the system resolver** (#123). Hosts the public
  resolvers do not answer (an internal zone, a Docker or Kubernetes service
  name) are queried once more through the nameservers in
  `/etc/resolv.conf`, as naabu (`-sr`), httpx and nuclei already reach them.
  Names the public resolvers answer keep their public answer.
- **CI mode pushes with the run's context** (#125), not
  `context.Background()`: Ctrl-C/SIGTERM stops an in-flight push, and a
  command id on the context reaches the SDK, which binds the results to it.
- **CodeQL findings carry their CWE.** CodeQL puts a rule's CWE only in its
  tags (`external/cwe/cwe-079`); the parser read a `cwe` property CodeQL does
  not emit, so every CodeQL finding reached the platform with no CWE. The
  tags are now read, and CWE ids are normalized to `CWE-<n>` (no leading
  zeros, no duplicates).

## [v0.8.0] — 2026-10-03

### Upgrading

- **Custom nuclei templates need the tenant's template-signing key.** Pin
  the tenant's public key in `SENSOR_TEMPLATE_SIGNING_KEYS` (base64 Ed25519,
  comma-separated during a key roll), fetched by a tenant admin from
  `GET /api/v1/scanner-templates/signing-key` on a platform API that
  includes openctem#869 (older APIs neither serve the key nor sign the
  templates). Set `SENSOR_ID` as well to bind manifests to this sensor.
  Without the key, a scan that carries custom templates fails before nuclei
  starts. Scans without custom templates are unaffected.
- **New nuclei rate ceilings.** `SENSOR_NUCLEI_MAX_RATE_LIMIT`,
  `SENSOR_NUCLEI_MAX_CONCURRENCY` and `SENSOR_NUCLEI_MAX_BULK_SIZE` (default
  150, 25, 25: nuclei's own defaults) cap `-rate-limit`, `-c` and `-bs`,
  which are now always passed. A scan may ask for less, never more. A
  value outside 1..1000000 stops the sensor at start, so check these
  variables if you set them. Rate-limit flags in a scan's extra args are
  now refused.
- **Pipeline step config is honored.** A platform pipeline step's settings
  now reach the tool: naabu `ports`, `top_ports`, `exclude_ports`, `rate`,
  `retries` and nuclei `tags`, `exclude_tags`, `severity` (see Fixed
  below). Steps that set them used to run with the tool's defaults; after
  the upgrade they scan what the step says (for example only `ports: "80"`).
  An invalid value now fails the command instead of being ignored.
- **`-dut` (`-disable-unsigned-templates`) is always on** for the sensor's
  own nuclei templates (managed content, the image's templates and
  `validate:nuclei` re-verification), also in a scan that carries custom
  templates, which now run in a separate nuclei run. `-dut`,
  `-disable-unsigned-templates` and `-dut=false` in a scan's extra args are
  refused (sdk-go), so the check cannot be turned off per scan; an unsigned
  or locally modified template in the sensor's template directory is
  skipped.

### Security: nuclei template trust and rate-limit ceilings

- **Signed templates only, always.** Every nuclei run of the sensor's own
  templates passes `-disable-unsigned-templates`, also without managed
  content (the image's templates) and for `validate:nuclei` re-verification.
  Before, a scan that carried custom templates dropped the flag for the whole
  run, so the official set ran unchecked next to them.
- **Custom templates run apart.** A scan with custom templates is two nuclei
  runs: the sensor's own set (signature-checked), then the custom templates
  alone with `-exclude-type code,file,headless,javascript` and never
  `-headless`. Before nuclei starts, `CheckCustomTemplates` refuses a custom
  template that uses the `code`, `javascript`, `file` or `headless` protocol
  or is self-contained.
- **Custom templates must carry the platform's signed manifest** (sdk-go:
  a DSSE envelope binding tenant, sensor, command, expiry and every
  template's SHA-256): pin the tenant's key in `SENSOR_TEMPLATE_SIGNING_KEYS`
  (and set `SENSOR_ID` to bind manifests to this sensor). **Upgrade note:** without
  it, scans with custom templates fail; scans without custom templates are
  unaffected.
- **Rate-limit ceilings.** `SENSOR_NUCLEI_MAX_RATE_LIMIT`,
  `SENSOR_NUCLEI_MAX_CONCURRENCY` and `SENSOR_NUCLEI_MAX_BULK_SIZE` (default
  150, 25, 25) cap `-rate-limit`, `-c` and `-bs`, which are now always
  passed. A scan can ask for lower values (`rate_limit`, `concurrency`,
  `bulk_size`), never higher; rate-limit flags in extra args are refused.
  An invalid ceiling stops the sensor at start.

### Changed

- sdk-go v0.17.0 (the tag), which carries the signed custom-template
  manifests, more refused nuclei flags, capped scan limits and typed scan
  settings this release uses, and removes the SDK copies of the tool
  wrappers (this repository has owned them since v0.7.0; nothing here
  imported them).

### Fixed: a pipeline step's settings reach naabu and nuclei

A platform pipeline step's config (for example `ports: "80"` for naabu, or
`tags` for nuclei) had no effect: the SDK's command executor dropped every
config key but `allow_interactsh` and `exclude`, so every step ran with the
tool's defaults. With sdk-go's typed settings (api RFC-038) naabu and nuclei now declare what a scan
may set, and each value maps to one specific flag of a per-scan copy of the
tool:

| Tool | Key | Flag | Rules |
|---|---|---|---|
| naabu | `ports` | `-p` / `-top-ports` | a port list (`80,443,8000-8100`, ports 1-65535) or `top-100`, `top-1000`, `full` |
| naabu | `top_ports` | `-top-ports` | 100 or 1000; not together with `ports` |
| naabu | `exclude_ports` | `-exclude-ports` | a port list |
| naabu | `rate` | `-rate` | can only lower the sensor's rate, never raise it |
| naabu | `retries` | `-retries` | 0-10 |
| nuclei | `tags` | `-tags` | lowercase tags; `dos`, `fuzz`, `fuzzing`, `intrusive` refused |
| nuclei | `exclude_tags` | `-etags` | added to the sensor's exclusions, never replacing them |
| nuclei | `severity` | `-severity` | `info` to `critical`, `unknown` |

A value outside these rules fails the command before the tool runs (no
flag, separator or newline can get through). Template paths, protocols
(code, file, headless), proxies, interaction servers, output paths, the
naabu scan type and nmap are not settable. Other config keys are reported
in the result's `ignored_config_keys` instead of vanishing.

## [v0.7.0] — 2026-10-03

### Changed: sdk-go v0.16.0 (the tag)

The sensor builds against the sdk-go v0.16.0 tag instead of the
pre-release commit c82fe0d it was pinned to. Over that commit v0.16.0 adds
only API the sensor does not use yet (the conformance suite
`conformance.RunSensorSuite`, `Client.PlatformSupports`, the tool settings
schemas of api RFC-038) and the deprecation of the sdk-go copies of the
tool wrappers this repository now owns; it changes nothing the sensor runs.

### Added

- **Recon tools for EASM discovery** (api RFC-036 P0). The full and platform
  images ship subfinder 2.16.0, dnsx 1.3.1, naabu 2.6.1, httpx 1.12.0 and
  katana 1.7.0 (SHA-256 pinned per architecture, each must answer `-version`
  at build time, non-root, no libpcap or CAP_NET_RAW: naabu runs a TCP
  connect scan). The daemon detects them like the other tools, reports them
  only when the binary answers its version flag, and runs dispatched jobs for
  them: each target is scanned and the hosts, IPs, services and URLs found go
  to the platform as assets (one CTIS report per job, converted by the SDK's
  `ctis.ConvertReconToCTIS`). Non-intrusive defaults (RFC-036 O3): naabu top
  100 ports, katana without form filling or a headless browser. The tool
  wrappers live in `internal/recon` (moved from sdk-go `pkg/scanners/recon`,
  with their flags checked against each pinned tool's `-h` and their output
  parsing fixed against real output).

### Changed: the tool wrappers live in the sensor (sdk-go keeps the runtime and safety layer)

The scanner wrappers and parsers the sensor runs moved from sdk-go into the
sensor: `internal/scanners` (nuclei, trivy, semgrep, betterleaks, codeql,
and their report helpers; the scanner registry now registers the recon
tools from `internal/recon`, which #111 already moved),
`internal/handler` and `internal/strategy` (CI mode), and `internal/assetctx`
(with `internal/cirepo`, its CI repository detection). They were copied
unchanged from sdk-go `main` (c82fe0d, so they include sdk-go#129's recon
fixes and #130's Interactsh-off default) and keep calling sdk-go `core` for everything
security-relevant: `ExecuteScanner` / `StreamScanner` (process group,
output caps, scanner priority), the scanner environment allow-list and
`core.ValidateExtraArgs`. The move itself changes no behaviour (the moved
tests run here); the sdk-go bump below brings the SDK fixes made since the
previous pin (v0.15.0: bounded scanner output, extra-args guard in every
scanner, outbox key refusal; then the recon and Interactsh fixes above).
The sdk-go copies are deprecated in sdk-go v0.16.0 and removed in v0.17.0.

- sdk-go is pinned to c82fe0d (after v0.15.0): the copied wrappers call
  `core.ValidateExtraArgs` and use `core.ScanOptions.AllowInteractsh`.

### Security: tool probes get the scanner environment

`<tool> --version`, run by `-list-tools` and, in the daemon and one-shot
runs, to explain why a configured scanner is unavailable, inherited the
sensor's whole environment, `API_KEY` included. It now gets the same allowlisted
environment as scans (`core.ScannerEnviron`): no `API_KEY`, `SENSOR_*` keys,
tokens or passwords. The interactive `-install-tools` installers still run
with the operator's environment, as before.

### Removed: platform mode (`-platform`)

`-platform` spoke `/api/v1/platform/register`, `lease` and `poll`, which the
API no longer serves, so a `-platform` sensor could never connect. It and the
code only it reached are gone: `platform.go`, the `platform` build tag, the
platform executors in `internal/executor` (vulnscan, recon, secrets, the
Tenable runner, the router), `internal/security/targetguard` and
`internal/config`. Without the recon executors' `hybrid` build, the
projectdiscovery libraries (subfinder, dnsx, naabu, httpx, katana) leave
`go.mod`. The server-controlled daemon (`-daemon -enable-commands`, the
image's default command) is unchanged.

- `-platform` now exits with code 2 and says what to run instead.
  `-bootstrap-token`, `-enable-recon`, `-enable-vulnscan`,
  `-enable-secrets`, `-enable-assets` and `-enable-pipeline` are still
  accepted and ignored, so an old command line reaches that message
  instead of "flag provided but not defined".
- `-name` / `SENSOR_NAME` now names the daemon. Only platform mode read it
  before; the daemon called itself `sensor-<hostname>` whatever was set.

### Changed: hardened images (no package installer, pinned bases, non-root CI images)

- **No pip in any runtime image.** The python images deleted-and-replaced
  pip only to patch its CVEs; they now delete it (and ensurepip's bundled
  wheel) after copying semgrep's site-packages. semgrep does not need it.
  apt/dpkg stay: the Debian base cannot run without dpkg.
- **Base images pinned by digest** (`image:tag@sha256:...`) in all five
  Dockerfiles. Dependabot cannot query ECR Public, so digests are bumped by
  hand; the Dockerfile header has the command.
- **CI images run as a non-root user.** `-ci`, `-semgrep`, `-betterleaks`,
  `-trivy` and `-nuclei` (and `trivy-ci`) now run as `openctem`, uid/gid
  1001, the GitHub-hosted runner's user that owns `/github/workspace`.
  git trusts only `/github/workspace` (system config) instead of every
  directory (`safe.directory '*'`). The trivy cache and nuclei templates
  moved under `/home/openctem`.
  - **Upgrade note.** On a runner whose checkout is owned by another user
    (GitLab, self-hosted runners), git refuses the checkout as "dubious
    ownership". The GitLab templates in `ci/gitlab/` now trust the job's
    checkout through `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory`,
    `GIT_CONFIG_VALUE_0=$CI_PROJECT_DIR`; elsewhere, set the same variables
    or run the container as the checkout's owner
    (`docker run --user "$(id -u):$(id -g)"`, GitLab `image:docker:user`).
    The checkout must be writable by uid 1001 (or that user) for report
    files.

### Fixed: platform-mode scanners and content refresh run as scanners (api RFC-035 B6)

With sdk-go openctemio/sdk-go#113. The platform-mode tools (nuclei, trivy,
semgrep, and the recon CLI tools) and the content refresh (trivy DB
download, nuclei template update) now start through the SDK's scanner
process handling (`internal/scanproc`):

- **Own process group.** A canceled or timed-out scan kills the whole
  group, including the children of a wrapper script; before, only the
  direct child was killed. Leftover background children are killed when
  the tool exits.
- **Scanner priority.** They run at `SENSOR_SCANNER_PRIORITY` (default
  `low`: nice +10, lowest best-effort I/O, `oom_score_adj` 500). When
  memory runs out, the kernel kills a scanner before the sensor. Platform
  mode (`-platform`), which does not run on sensorkit, now reads
  `SENSOR_SCANNER_PRIORITY` too (an invalid value exits with code 2).

Error reporting is unchanged: a failed nuclei or trivy run still reports
its standard error.

### Added: proxy settings per outbound path (api RFC-034 Phase 0)

With sdk-go openctemio/sdk-go#111:

- **Two new settings:**
  - `SENSOR_CONTROL_PROXY` for traffic to the platform;
  - `SENSOR_CONTENT_PROXY` for content and feeds.

  Each takes a proxy URL or `direct`. When it is unset, traffic follows
  `HTTP(S)_PROXY` / `NO_PROXY`, as before.
- **Scanners and the proxy.** `SENSOR_SCAN_PROXY=inherit|direct` says
  whether scanner processes get the sensor's proxy variables.
  - `inherit` stays the default.
  - The sensor now warns at start when scanners inherit a proxy, because
    internal targets would go through it.
- **Content downloads work behind a proxy-only egress.** nuclei templates
  and semgrep rules from upstream sources used to ignore the proxy.
  - The target is checked before the proxy is used.
  - Content tools (trivy's DB download) follow the content proxy.
  - `SENSOR_CA_CERT_FILE` is trusted for content too.

### Fixed: nuclei version, per-tool capabilities and the reported concurrency

With sdk-go openctemio/sdk-go#106:

- nuclei's version is reported (`v3.11.1`). nuclei prints it only to
  stderr, in color, and the probe read stdout.
- Each tool on the heartbeat says what it serves (`nuclei` → `dast`,
  `validate:nuclei`; `semgrep` → `sast`), so the platform shows which tool
  provides each capability.
- Without `SENSOR_MAX_JOBS` the heartbeat no longer reports
  `max_concurrent_jobs: 64` (the SDK's upper bound). It reports what the
  sensor can run now (`capacity.slots_total`, from its CPU and memory),
  and the operator's cap only when one is set.

### Changed: the renewed API key survives a restart; renewal on by default on persistent state

- With sdk-go's sensorkit (openctemio/sdk-go#104) the daemon reads and
  writes its API key in the state directory (`SENSOR_STATE_DIR`, default
  `/var/lib/openctem/state`): a renewed key is saved there and preferred
  over `API_KEY` on the next start, unless `API_KEY` was changed to a
  regenerated key (api RFC-032 Phase 0). A
  `~/.openctem/sensor-credentials.json` from an earlier version is moved
  there. The tool cost history moves to the state directory too.
- Key auto-renewal defaults to **on when the state directory is on a
  persistent volume** (or outside a container) and off otherwise, with the
  reason logged. `PLATFORM_KEY_AUTORENEW=true|false` or `-key-autorenew` /
  `-key-autorenew=false` force it.
- The images create `/var/lib/openctem/state` (0700, the sensor user) and
  declare `/var/lib/openctem/content` a volume next to the outbox; state is
  deliberately not a `VOLUME` (an anonymous volume is lost with the
  container). Mount a named volume or a PVC at
  `/var/lib/openctem/state`.
- Every heartbeat carries the process's `instance_id` (sdk-go), so the
  platform flags a key running in two places.

### Changed: the daemon runs on the SDK's sensor runtime (sdk-go `pkg/sensorkit`)

- The platform plumbing moved into sdk-go `pkg/sensorkit`: settings
  resolution, `AGENT_*` migration, heartbeat, doorbell, key renewal, startup
  auth wait, command poller and slots, outbox, and drain. Any sensor gets it
  with one call, so this repository keeps only its tools: scanners,
  executors, scanner content and image tool probing.
- **Nothing changes for operators.** Flags, environment variables, exit
  codes, log lines and the v1/v2 wire are the same. A recorded fake
  platform shows the same requests and heartbeat bodies before and after,
  in 14 scenarios.
- One small difference: a scanner whose name was retired (`gitleaks`) logs
  its "replaced by" note once instead of once per internal lookup.
- New, optional: `SENSOR_CA_CERT_FILE` names a PEM file with the platform's
  private CA. That CA is then trusted for platform requests, in addition to
  the system roots.


### Changed: the sensor finds its own tools; `SENSOR_TOOLS` is optional

- A server-controlled daemon (`-daemon -enable-commands`) given no tool list
  (no `-tool`, `-tools`, `SENSOR_TOOLS` or config-file scanners) probes the
  native scanners (semgrep, betterleaks, trivy, nuclei) at start-up and
  runs the ones that are installed. It logs them ("Tools: ... (detected; set
  SENSOR_TOOLS to limit)") and reports them on every heartbeat. The image
  variant decides the tool set. The platform needs no tool list for a
  sensor (api RFC-029 §4.3.1).
- `SENSOR_TOOLS` / `-tools` still works, now as an optional operator
  allowlist: only those scanners run and are reported. The `-default` image
  no longer sets it. An explicit list behaves exactly as before.
- The heartbeat inventory is the SDK's tool registry (`BaseSensor.Tools`,
  sdk-go#99) instead of the daemon's own reporter. The report is the same,
  and each tool also carries `kind: scanner`.
- `-content-status` / `-content-refresh` without a list use the installed
  tools.

### Security: signed images and release archives

- Every image `docker-publish.yml` pushes is signed by digest with cosign
  keyless signing (`--recursive`: the multi-platform index and each
  platform's manifest), then verified in the same job; the Docker Hub copies
  are signed too. `release.yml` signs `checksums.txt`
  (`checksums.txt.sigstore.json`). The certificate names the workflow at the
  release tag, so `cosign verify --certificate-identity ...` proves an image
  or archive was built by this repository's release pipeline (README,
  "Verifying images and releases"). This is the trust root the platform's
  managed sensor updates rely on (api RFC-031).

### Added

- **The daemon reports what it really has** (api RFC-029 §4.3.1). Every
  heartbeat lists every configured scanner, with its version from the
  scanner's own install check (`installed: false` when it is missing or
  fails to run) and its content. It also lists the capabilities the daemon
  serves: each installed tool's name, its sast/sca/secrets/iac/container/dast
  category, `validate`, and `validate:nuclei` with nuclei, when commands are
  on. When an operator cap is set (`sensor.max_jobs`, `-max-concurrent`,
  `SENSOR_MAX_JOBS`), the heartbeat reports it as `max_concurrent_jobs`.
  The platform dispatches by the report: a scan for a tool goes only to
  sensors that have it, and its administrator can only narrow the report.
  Tools are probed at start and at most every 10 minutes.
- **Managed scanner content** (api RFC-031). The daemon refreshes the trivy
  vulnerability DB, the nuclei templates and (when rulesets are chosen) the
  semgrep rules on a schedule and on the platform's `refresh_content`
  command; verifies each download (OCI digest and trivy metadata,
  release-checksum sha256 and a nuclei load check, a semgrep load check),
  swaps it in atomically and keeps the previous version. Scans use exactly
  the current version (`--cache-dir … --skip-db-update`, `-t … -disable-update-check
  -disable-unsigned-templates`, `--config <rules>`), so trivy no longer
  downloads its DB mid-scan and nuclei no longer updates its templates by
  itself. The heartbeat reports each tool and its content
  (`tools[].content`), results carry `tool.properties.content`. Mirrors and
  local files for air-gapped hosts; the platform's policy can pin versions
  and set a maximum age but never a source. `SENSOR_CONTENT=off` restores
  the old behaviour. See "Scanner content updates" in the README.
- `-content-status`, `-content-refresh` and `-content-force`.
- Content reports `checked_at` (the last check that confirmed it is the
  newest or pinned version); old content whose source has nothing newer is
  no longer stale (sdk-go `ContentInfo.Stale`). A pinned nuclei-templates
  release carries its publication date; a pin added, changed or removed
  moves the content; every `refresh_content` result lists each content in
  exactly one of refreshed/unchanged/skipped (with a reason)/failed; one-shot
  and scheduled results carry `tool.properties.content` too.

### Upgrading to protocol v2 (read this)

The OpenCTEM platform (api v0.9.0) serves the whole sensor protocol under
`/api/v2/sensor/*` and deprecates the old `/api/v1/agent/*` routes
(`Deprecation`, `Sunset: Thu, 01 Apr 2027 00:00:00 GMT`; api RFC-029). This
release speaks v2 for everything such a platform offers.

- **Running our sensor:** use this release (`ghcr.io/openctemio/sensor:v0.5.0`,
  or `go install github.com/openctemio/sensor@v0.5.0`). No configuration
  change. Against an older platform it falls back to v1 by itself.
- **Check:** the platform's Sensors page shows the sensor on protocol v2, or
  `GET /api/v1/sensors/{id}` returns `"protocol": {"version": 2, ...}` after
  its next heartbeat. A sensor still on v1 is shown as deprecated.
- `SENSOR_PROTOCOL=v1` keeps the old requests byte for byte (and logs a
  deprecation warning once when the platform deprecated them).

### Changed

- **Protocol v2 for the whole sensor surface** (sdk-go v0.9.0, api RFC-029):
  heartbeat, command poll and claim/start/complete/fail, suppressions (the
  `-fail-on` gate), fingerprint check and PR baseline-diff, and key renewal
  (`-key-autorenew`) use `/api/v2/sensor/*` when the platform lists them on
  `GET /api/v2/sensor/hello`; results did since v0.4. The sensor is
  identified by its key alone: no `X-Agent-ID` on v2. Command transitions are
  idempotent on v2, so a completion whose answer was lost no longer fails the
  command.
- `-protocol` / `SENSOR_PROTOCOL` / `server.protocol` now name the sensor
  protocol, not only the results protocol; values are unchanged.
- Requests carry `User-Agent: openctemio-sensor/<version> openctem-sdk-go/<version>`,
  which the platform shows per sensor next to its protocol.

### Fixed

- **No duplicate scans from over-claiming** (api RFC-030 Phase 0, sdk-go
  #92). The daemon takes a free slot before it claims a command, asks the
  platform for no more commands than its free slots, and does not run a
  command whose start the platform refused. Before, it claimed up to 10
  commands with 5 slots; the platform re-queued the waiting ones after 10
  minutes and another sensor scanned the same assets.
- **Concurrency follows the resources, no fixed 5** (sdk-go #93). The daemon
  sizes its slots from the CPU and memory it may use (cgroup v2/v1 aware)
  and its tools' learned cost, halving after OOM kills, timeouts or CPU
  throttling; the cost history is kept in `tool-costs.json` in the state
  directory (`SENSOR_STATE_DIR`, default the outbox's parent,
  `/var/lib/openctem` in the images). `-max-concurrent`, `SENSOR_MAX_JOBS`
  or `sensor.max_jobs` (1-100) is now a cap, not a count; unset means no
  cap (platform mode keeps 5). The heartbeat reports the cap
  (`max_concurrent_jobs`), the live slots and per-tool costs (`capacity`),
  the resources (`resources`), the local queue (`queue`) and the held
  command ids (`running`).
- **SIGTERM really drains** (api RFC-030 E2E F3/F4). The daemon exited at
  once on SIGTERM, before the poller could drain: running scans were left
  `running` on the platform and their processes outlived the sensor. It now
  waits for the drain (`SENSOR_DRAIN_GRACE`, default 30s): running scans
  finish, or are stopped (their whole process group, sdk-go #97) and
  released to the platform. A second signal stops at once. Orchestrators
  should allow the grace plus ~15 s before SIGKILL (Docker
  `stop_grace_period`, Kubernetes `terminationGracePeriodSeconds`; Docker's
  default is 10 s).
- **The first heartbeat precedes the first poll** (F2) and carries the
  capacity report, so the platform knows the sensor's cap before handing
  it work. A command's slot is reused only after its result reached the
  platform (sdk-go #95, F1).
- **Graceful stop** (sdk-go #93): on SIGTERM the daemon stops claiming,
  lets running scans finish for 30 s, then cancels them and releases them
  to the platform so another sensor takes them at once; a command the
  platform cancels is stopped and released. Per-host politeness: one
  command per target host at a time unless the command allows more.
- **Platform mode: a failed scan is reported failed** (api RFC-030 B12). A
  nuclei/trivy/semgrep run that exited with an error, timed out or was
  killed was reported `completed` with 0 findings, i.e. "scanned clean";
  findings that could not be delivered were also reported `completed`.
- **Sensors report their version and hostname** (sdk-go v0.8.1). The heartbeat
  never filled them, so the platform's Sensors page showed "No host info".

### Changed

- **Results use protocol v2 when the platform offers it** (sdk-go v0.8.0,
  api RFC-026). `SENSOR_PROTOCOL` / `-protocol` / `server.protocol`:
  `auto` (default; asks on the heartbeat, falls back to v1 against an older
  platform), `v1` (byte for byte the old requests) or `v2`.
- **The Go module is `github.com/openctemio/sensor`** (was
  `github.com/openctemio/agent`; the repository was renamed), so
  `go install github.com/openctemio/sensor@latest` works. Docs, CI
  templates and image source labels point at `openctemio/sensor`; the frozen
  `ghcr.io/openctemio/agent:*` images are unchanged.
- sdk-go v0.8.0 (the tag).
- `-retry-queue` / `RETRY_QUEUE=true` now turn the outbox on (also for a
  one-shot run); `RETRY_DIR` is imported from once. The old retry queue is gone.

- **Betterleaks replaces gitleaks as the secret scanner.** Betterleaks is
  gitleaks' successor by its original author: v1 keeps the gitleaks CLI,
  config format and JSON report, and adds BPE-token filtering, Expr filters
  and validation, recursive decoding and archive scanning. The images bundle
  betterleaks 1.9.0 (SHA-256 pinned per architecture), the `-gitleaks` image
  variant is now `-betterleaks` (old `-gitleaks` tags stay pullable, frozen),
  the `-default` image's `SENSOR_TOOLS` is `semgrep,betterleaks,trivy,nuclei`,
  and the CI templates use `betterleaks`. A command, config or template that
  says `gitleaks` runs betterleaks (sdk-go `core.CanonicalScannerName`).
  Fingerprints of secrets both tools report do not change. See
  [Upgrading: gitleaks → Betterleaks](README.md#upgrading-gitleaks--betterleaks).
- **The scanner no longer prints raw secrets into the sensor log.** In
  verbose mode the tool ran with `--verbose`, which prints each finding with
  its secret; it no longer does.
- The repository's own secret scan (Security workflow, pre-commit, `make
  security-scan`) uses betterleaks; the workflow job runs on every push and
  pull request and uploads SARIF (the gitleaks-action job was opt-in behind a
  licence and never ran).

### Fixed

- **The retry queue was never on**: `-retry-queue` / `RETRY_QUEUE=true`
  created nothing (the SDK ignored the setting) and the daemon logged
  "Could not start retry worker". Replaced by the outbox (Added).
- **A command was reported complete before its results arrived**, or even
  when they failed. The command result now waits behind its results and
  turns "failed" when the platform refuses them.
- **Scheduled daemon scans and platform-mode scans file findings on the
  scanned repository.** Their findings had no asset, which protocol v2
  rejects; dispatched and one-shot scans already named it.

- **A rejected API key no longer restart-loops the daemon.** It exited on a
  401 at start-up, and the container restart policy relaunched it at once (12
  restarts and 12 requests in 3 minutes under `docker --restart=always`, each
  repeating the plain-http warning). The daemon now stays up, stops polling
  and re-checks with a capped backoff (30 s doubling to 10 min), logging one
  actionable line per attempt without `-verbose`, and resumes on its own once
  the key is accepted. Mid-run rejections (revoked, regenerated or deleted
  sensor) back off the same way instead of a heartbeat and a poll every
  interval. A 401 `API key required` says that `API_URL` points at the web UI
  or a header-stripping proxy.
- **One-shot runs exit with code 78 (`EX_CONFIG`) on a rejected key**, with
  the same message.
- **Daemon start-up sends one heartbeat, not two**: the first heartbeat is the
  connection check.
- **semgrep works in the images again.** Every v0.3.0 image that bundles
  semgrep (`-default`, `-ci`, `-semgrep`) shipped semgrep 1.93.0, whose
  opentelemetry-instrumentation 0.46b0 imports `pkg_resources`; setuptools
  81 removed it, so `semgrep --version` died with `ModuleNotFoundError` and
  the sensor skipped semgrep ("Scanner semgrep not installed, skipping").
  The images now install semgrep 1.178.0 against a pinned dependency set
  (`docker/semgrep-constraints.txt`), and the build runs `semgrep --version`.
- **The `-default` image connects with its own defaults.** Its command was
  `-platform -verbose`, a mode that uses `/api/v1/platform/register`,
  `lease` and `poll`, which the API does not serve. The default is now the
  server-controlled daemon, `-daemon -enable-commands -verbose`, running the
  tools in the new `SENSOR_TOOLS` variable (the image sets
  `semgrep,gitleaks,trivy,nuclei`; `-tool`/`-tools` still win).
- **A server-controlled daemon without `API_URL`/`API_KEY` says so.** It
  used to start, never poll, and never say why. It now exits with code 2,
  names the missing variables and shows how to set them.
- **A broken tool is no longer reported as "not installed".** The sensor
  tells a missing binary from one that is installed but fails to run, and
  prints the tool's own error ("Scanner semgrep skipped: installed but fails
  to run: ... ModuleNotFoundError: No module named 'pkg_resources'").
  `-check-tools` shows `INSTALLED BUT BROKEN`, and `-list-tools` now shows
  each native scanner's state (`available: <version>`, `not installed`,
  `BROKEN: ...`) and lists nuclei.

### Added

- **Durable outbox (on by default with `-daemon`).** Every result is written
  to `/var/lib/openctem/outbox` (else `~/.openctem/outbox`) before it is
  sent and deleted only once the platform accepted it: a crash, `kill -9`,
  an API outage or a restart loses nothing, and the backlog is delivered
  oldest first as soon as a heartbeat gets through. Refused results go to
  `dead/` with the reason; a 1 GiB / 7 day cap drops the oldest with a
  warning. Files are 0600, encrypted (AES-256-GCM, key created on first
  start), one sensor per directory. Settings: `SENSOR_OUTBOX` (on/off),
  `SENSOR_OUTBOX_DIR` / `-outbox-dir`, `SENSOR_OUTBOX_MAX_BYTES`,
  `SENSOR_OUTBOX_MAX_AGE`, `SENSOR_OUTBOX_KEY_FILE`, or the `outbox:`
  config block. `-outbox-status` and `-outbox-requeue-dead` inspect it.
  The heartbeat reports its state to the platform.
- **The `default`, `full` and `slim` images declare
  `VOLUME /var/lib/openctem/outbox`**, owned by the image's non-root user.
  Mount a named volume there (README and QUICK_START show `docker run` and
  Compose).

- **Image smoke test.** `scripts/image-smoke-test.sh` runs every bundled
  tool's version command and checks `-list-tools` reports each one
  available (and, for `-default`, the default command and the missing-
  credentials error). It runs for every variant on pull requests that touch
  the images (`image-smoke.yml`) and gates `docker-publish.yml` before any
  image is pushed.

## [v0.3.0] — 2026-10-01

First release under the *sensor* name (binary `openctemio-sensor`, images
`ghcr.io/openctemio/sensor:v0.3.0-<variant>`). The previous release was
v0.2.2 (2026-08-20, still named *agent*).

### Renamed: agent → sensor (RFC-023 §9.5)

The binary, images and settings move to the *sensor* vocabulary. Existing
installations upgrade in place with no manual step; the sensor refuses to
start only when an old and a new name are set to different values (the error
names both, never the values).

| Before | After | Upgrade |
|---|---|---|
| binary `agent` | `openctemio-sensor` (archives `openctemio-sensor_<version>_<os>_<arch>`) | — |
| images `ghcr.io/openctemio/agent:*` | `ghcr.io/openctemio/sensor:*` | old tags stay pullable and **frozen**: never re-pushed, never deleted |
| `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` | `SENSOR_ID`, `SENSOR_NAME`, `SENSOR_ALLOW_PRIVATE_TARGETS` | old name applied, startup `WARN deprecated configuration` naming both |
| `-agent-id` | `-sensor-id` | old flag applied, warning |
| `-config` file `agent:` block, `server.agent_id` | `sensor:`, `server.sensor_id` | old keys applied, warning |
| `~/.openctem/agent-credentials.json` | `~/.openctem/sensor-credentials.json` | moved on first start by the SDK: written 0600 with fsync, read back and compared, then the old file removed; same identity and key, no re-registration; used in place if it cannot be moved (read-only mount); `-credentials <path>` used as is |
| `API_URL`, `API_KEY`, `BOOTSTRAP_TOKEN` | unchanged | — |
| CI templates (`ci/`) | image `ghcr.io/openctemio/sensor:latest-<variant>`, command `openctemio-sensor` | — |

Built on sdk-go's sensor release (v0.7.0; until it is tagged, a pseudo-version
of its `refactor/sensor-rename` branch). The protocol v1 wire is unchanged, so
this sensor works with platforms from before and after the rename. The Go code
was renamed by `scripts/rename/sensor-rename.sh` (re-runnable, type-aware).
The repository itself keeps the name `openctemio/agent` until its owner renames
it.

### Added

- **Heartbeat doorbell** (API RFC-023 §9.2a, sdk-go v0.7.1). A daemon
  (`-daemon -enable-commands`) no longer polls for commands every 30 s when
  the platform supports the doorbell: it polls when a heartbeat reports
  waiting work (`pending_jobs`), plus a safety poll every 5 minutes, and
  heartbeats as often as the platform advises. `pause` (a disabled sensor)
  stops it taking new jobs while running jobs finish and heartbeats go on
  (logged as "paused by platform"); the first heartbeat without `pause`
  resumes it; `drain` is final until restart. Against an older API it polls
  every `command_poll_interval` as before. Opt out with `-disable-doorbell` /
  `sensor.disable_doorbell: true`.
- `-key-autorenew` now works in daemon mode too: the key is renewed at half
  its lifetime and at once when the platform's heartbeat asks (`rotate_key`),
  and saved to the `-credentials` file, whose key the next start uses.

- **Executors** — safe-check validation executor (RFC-011), Tenable runner mode
  (RFC-007 §3.10), and a risk-aware CI gate that blocks on actively-exploited
  findings below the configured threshold.
- **PR-scoped scanning** — baseline-diff so a pull-request scan reports only what
  the PR introduces, with results posted back as comments (RFC-008 Phase 3).
- **Auto-resolve for manual scans** — a full-repo scan outside CI now closes
  findings it no longer sees, matching the CI path.
- **Agent API-key auto-renewal** (RFC-014 Phase 2) — the agent renews its own
  credential before expiry rather than failing closed at rotation time.
- **Asset-name normalisation in recon parsers** (RFC-001), so discovered assets
  correlate with what the platform already knows instead of arriving as
  near-duplicates.
- **`--allow-private-targets`**, opt-in, for scanning internal networks. Off by
  default; see the SSRF guard below for what it relaxes and what it cannot.
- Multi-arch Docker publish and image security scanning.

### Security

- **Scanner target SSRF guard.** Two tiers: a hard block that no flag can open
  (cloud metadata endpoints, loopback, CGNAT, multicast, broadcast, IPv6
  link-local) and a soft block for RFC1918 + IPv6 ULA that
  `AGENT_ALLOW_PRIVATE_TARGETS` opts out of. Shared design with
  `api/pkg/httpsec` and `sdk-go/pkg/httpsec`; CI asserts the three CIDR tables
  stay in parity.
- **`dangerousToolFlags`** — an explicit deny-list of scanner flags that would
  turn a scan into arbitrary execution or a file read on the agent host.
  Completeness is CI-enforced.
- **Runner target-guard** (RFC-007 §8 R1) — blocks metadata and loopback
  targets and bounds scan ranges, so a runner cannot be pointed at the host it
  runs on.
- **`ExtraArgs` validation and bounds checking**, closing the gap where
  operator-supplied arguments reached a scanner unchecked.
- **Supply-chain verification in the image build** — gitleaks, trivy, nuclei and
  semgrep binaries are SHA-256 verified against published checksums at build
  time, so a compromised upstream download does not silently become part of the
  image.
- **Agent audit fixes** — SSRF guard, gate now fails closed rather than open, a
  secret leak in output, and scan bounds.
- **Go toolchain kept current for stdlib CVEs** — 1.25.7 (GO-2026-4337), 1.25.8,
  then 1.26 (five stdlib vulnerabilities). Currently `go 1.26`.

### Fixed

- **The sensor connects to a platform on a private network again** (sdk-go
  v0.7.2). Since v0.2.x a platform on loopback, a Docker or Kubernetes
  network, RFC1918, ULA or Tailscale/CGNAT addresses was refused with
  `ssrf guard: blocked IP` on every heartbeat unless
  `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE=1` was set. That setting is no longer
  needed to reach the platform; remove it unless you want scanners to reach
  private targets too (that is `SENSOR_ALLOW_PRIVATE_TARGETS=1`).
  `HTTPS_PROXY` / `NO_PROXY` are honored for platform traffic again.
- **A misread scan-target setting stops the sensor at startup** (sdk-go
  v0.7.3). `SENSOR_ALLOW_PRIVATE_TARGETS` only accepts `1`; `true`, `yes` or
  `on` used to be ignored silently, refusing every private target. The
  sensor now exits with a message naming the variable, as it does when the
  sensor and pre-rename (`AGENT_*`) names disagree.

- **Scans dispatched by the server now deliver their findings.** Before, the
  command lifecycle completed but no results arrived:
  - nuclei output had no parser and the SARIF fallback read it as 0 findings
    (or failed). The nuclei parser is registered, and output no parser reads
    now fails the command instead of reporting 0 findings.
  - gitleaks, semgrep and trivy fs targets were refused ("DNS lookup failed for
    scanner target /…/repo"): the SSRF guard resolved filesystem paths as
    hosts. Targets are now checked by scanner type; code-scanner paths are
    confined to the scan workspace (`SENSOR_SCAN_ROOTS`, default the working
    directory) instead.
  - every custom-template scan failed with a hash mismatch (sdk-go hashed the
    base64 text; the platform hashes the template).
  - chunked uploads attributed later chunks to tool `unknown` on a placeholder
    asset (sdk-go now makes every chunk self-describing).
  - a dispatched filesystem scan's findings now land on the repository asset
    (its git remote) rather than a placeholder.
- A daemon with `-enable-commands` no longer scans its working directory with
  every configured scanner at start and hourly; it scans only what the server
  dispatches, plus targets configured explicitly.
- CI templates referenced Docker Hub images that were never published
  (`openctemio/sensor:ci` and others). They now use
  `ghcr.io/openctemio/sensor:latest-<variant>`, and the release pipeline
  publishes a `ci` variant (semgrep + gitleaks + trivy) for the full-scan job.
  GitLab jobs override the image entrypoint, which is the sensor binary.
- pgx bumped to v5.11.0 (CVE-2026-33815, CVE-2026-33816, CVE-2026-41889; an
  indirect dependency). x/crypto stays at v0.57.0, the latest: GO-2026-5932
  has no fixed release yet.
- The weekly security sweep never scanned the container image: the job was
  gated on `event_name == 'push'`, so the scheduled run skipped it and reported
  green. It had been reporting green without scanning for weeks.

### Tools invoked

`gitleaks`, `httpx`, `nuclei`, `semgrep`, `subfinder`, `trivy` — each behind the
target guard and flag deny-list above.

---

## Before this file

The agent has no tagged history. Commits before this point are visible with
`git log`, and the platform components it talks to have their own tags —
`api` and `ui` at v0.3.0, `sdk-go` at v0.5.2, `ctis` at v1.1.0.
