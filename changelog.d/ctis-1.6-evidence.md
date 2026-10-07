### Security: nuclei evidence is kept raw with credentials marked; retests prove a fix

- The sensor speaks CTIS 1.6.
- **Nuclei findings carry typed evidence.** Each finding carries the matched request and response, the curl command and the extracted values as `evidence_items`, raw, with every credential (Authorization, Cookie, Set-Cookie, credential query values) marked sensitive. The platform masks marked values for display and reveals them only to authorized users. Outside the evidence, no credential reaches the report: the web location (`finding.web.url`) keeps parameter names and drops every query value.
- **Retests and re-verification run nuclei with `-ms`.** A template that ran and did not match returns the attempt's HTTP exchange as the proof of the fix. A template whose requests failed is inconclusive, with an error class that never quotes the URL. Each verdict carries the `template_digest` of the template that ran.
- The re-verification run is never verbose: the raw request and response never reach the logs.
- katana reports CTIS 1.6 `endpoints` besides its `discovered_url` assets (descriptor 2.1.0 declares `endpoint`).

### Upgrade notes

- Nuclei findings move their URL from `location.path` to `finding.web.url`, and a URL's query values are dropped (names kept). Fingerprints of findings on URLs with user info, a query or a fragment change once.
- A retest `fixed` verdict needs the attempt's exchange (sdk-go). A nuclei retest whose run gave no exchange is `unverifiable` instead of `fixed`.
