### Security: CI templates run the sensor image by digest; the GitHub action verifies its signature

- The GitHub and GitLab templates in `ci/` pin every sensor image to a release by digest (`ghcr.io/openctemio/sensor:v0.9.1-<variant>@sha256:...`) instead of the moving `latest-*` tags. Each digest's cosign signature (keyless, issued to this repository's release workflow) was verified when it was pinned.
- `scripts/pin-ci-images.sh vX.Y.Z` resolves, verifies and re-pins the templates for a new release; it refuses a digest whose signature does not verify.
- The composite action (`ci/github/action.yml`) resolves `version` to a digest, verifies its signature (`verify_signature`, default on) and runs exactly that digest. Its `version` default is now a release tag instead of `latest`.
- `ci/README.md` documents verification with cosign v3 and how to enforce the gate (the templates start in rollout mode).

### Upgrade notes

- If you copied a template, replace its `latest-*` image references with the pinned digests, or run `scripts/pin-ci-images.sh` on your copy.
