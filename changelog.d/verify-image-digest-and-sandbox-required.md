### Security: sensors.sh runs the image digest it verified; the examples require the sandbox

- Every `deploy/multi/sensors.sh` command that starts or pulls an image
  (`add`, `pair`, `repair`, `up`, `start`, `upgrade`, `set-ca`, `set-policy`,
  `set-header`, `unset-header`) resolves the release tag to a digest, runs
  `cosign verify` on that digest (identity `docker-publish.yml@refs/tags/<tag>`,
  GitHub Actions issuer) and records it in `.env` (`SENSOR_IMAGE_DIGEST`).
  `compose.yaml` runs `image:tag@sha256:digest`. Before, only `upgrade`
  verified, and then pulled the tag again. A failed verification stops the
  command and changes nothing. The cosign helper image is pinned by digest.
- New flags: `--dry-run` (verify and print, start nothing) and `--skip-verify`
  (air-gapped mirrors with their own trust; loud, recorded in
  `sensors-audit.log`). Verifications and failures are logged there too.
- `deploy/multi/compose.yaml` and `docker-compose.example.yml` set
  `SENSOR_SANDBOX=required` besides `SENSOR_SANDBOX_NETWORK=required`.
- Upgrade note: a kit from before this change has a `compose.yaml` that cannot
  run a pinned image; run `./sensors.sh upgrade --self-update vX.Y.Z`. A
  per-sensor `image:` override in `compose.yaml` must be pinned by digest.
