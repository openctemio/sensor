### Upgrade notes: CTIS 2.0 results; upgrade together with the platform

- Every result is a CTIS 2.0 document (`application/vnd.ctis+json; version=2.0`). There is no 1.x output and
  no compatibility mode. **Upgrade the sensor together with the platform**: the minimum platform is the
  OpenCTEM release that carries its CTIS 2.0 switch. An older platform refuses every result of this
  sensor; upgrade the platform first.
- Built on `github.com/openctemio/ctis/v2`, `github.com/openctemio/contract` v1.1.1 and the CTIS 2.0 SDK.

### Behaviour change: CTIS 2.0 documents

- Asset types are the 2.0 ones: `domain_name` (was domain / subdomain), `web_origin` (was http_service /
  website), `ip_range` (was network), `service` assets linked from their host by `exposes` relationships
  (naabu), `container_image` for a Trivy image artifact. Tool manifests consume and produce these types;
  katana's crawled URLs are endpoints of their web origin (no `discovered_url` assets).
- How each target ended is in `metadata.targets` (done; failed with its class; skipped when the
  sensor-local policy refused it; unfinished), including the hosts a run could not fully cover (coverage
  gaps: edge block or challenge, rate limit, a host that stopped answering; a proxy-pool gap leaves its
  target unfinished). The `failed_targets`, `unfinished_targets`, `refused_targets`, `coverage_gaps` and
  throttling properties are gone.
- nuclei: one `rules[]` entry per template with `content_sha256` (the template's digest) and
  `content_path` (its place in the content pack); every finding names it by `rule_ref` with the same
  `rule_id`. The `template_digest`, `template_path` and `rule_source` finding properties are gone (a
  tenant template's rule carries `extensions["io.openctem"].rule_source`). Waves of one task share one rule
  per template.
- The content releases a scan used are `tool.content[]` (name, version, sha256) instead of
  `tool.properties.content`.
- asn reports an address's announced ranges as `ip_range` assets with `contains` relationships, and the
  origin system, holder and country in `technical.ip_address` (no `asn_*` properties).
- httpx security headers are `technical.http.security_headers` and web content captures are
  `extensions["io.openctem"].web_content` on the `web_origin`.
- Assets the sensor names (the scanned repository, the scan target) carry no properties; the branch and
  commit are in `metadata.branch`.

### Security: secret fingerprints only with the sensor key

- A secret enters a fingerprint only as HMAC-SHA256 with the sensor's per-installation key (CTIS recipe
  `ctis-fp/2`); without the key a secret finding carries no fingerprint and the platform computes its own.
  A fingerprint computed over the checkout path of a code scan is computed again over the repository-relative
  path, or left to the platform when it cannot be (a secret, a misconfiguration).
