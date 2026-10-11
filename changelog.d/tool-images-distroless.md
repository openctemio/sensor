### Changed: the -nuclei and -trivy images are distroless

- `sensor:<version>-nuclei` and `sensor:<version>-trivy` are built on
  `gcr.io/distroless/static-debian13`. They contain only the sensor, the tool
  (static Go binaries), the baked nuclei-templates or trivy DB, CA certificates
  and time zones: no shell, no git, no apt/dpkg. Same uid/gid (1001), `HOME`,
  working directory (`/github/workspace`), environment, entrypoint and command.
  The amd64 nuclei image goes from 119.5 MB to 61 MB compressed.
- Neither image ever ran git: the sensor and both tools read the workspace
  directly. `-betterleaks` (whose history scan runs `git log`) and `-semgrep`
  (Python) keep their Debian bases.
- These are daemon and scanner images, not CI job images: a CI system that runs
  job scripts inside the image (GitLab `image:`) needs a shell. Use
  `ghcr.io/openctemio/ci` for that. To debug, use `docker debug` or
  `kubectl debug`.
