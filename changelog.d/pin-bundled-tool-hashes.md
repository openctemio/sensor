### Security: every bundled tool binary is pinned by hash; images carry an SBOM and provenance

- trivy and nuclei were checked only against the checksums file of the same GitHub release, which is trust-on-TLS: a replaced release asset with a matching replaced checksums file would have been installed. Their archive SHA-256 per architecture is now pinned in the Dockerfiles (`TRIVY_SHA256_*`, `NUCLEI_SHA256_*`), as betterleaks and the recon tools already were.
- semgrep and its whole dependency set install with `pip install --require-hashes --no-deps` from `docker/semgrep-requirements.txt`, the same lock the openctemio/ci images use. pip itself comes from `docker/pip-requirements.txt` (hash-pinned). `docker/semgrep-constraints.txt` (versions only, no hashes) is removed. The build checks the installed pip and semgrep versions.
- Each published image now carries a BuildKit SBOM and a build provenance attestation (`provenance: mode=max`, `sbom: true`), as the ci images do.
- Upgrade notes: bumping trivy, nuclei or semgrep now means bumping the pinned hashes, or re-locking the requirements file, in the same change.
