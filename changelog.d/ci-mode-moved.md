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
