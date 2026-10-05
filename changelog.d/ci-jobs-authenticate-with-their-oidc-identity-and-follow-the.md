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
