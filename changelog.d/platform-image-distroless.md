### Changed: the default (platform) image is distroless, a third smaller, without Python, git or a shell

- `ghcr.io/openctemio/sensor:<version>` (the `-default` platform image) is now
  built on `gcr.io/distroless/base-nossl-debian13` (glibc, CA certificates,
  time zones) instead of `python:3.12-slim`. It holds the daemon, nuclei and
  the recon tools (subfinder, dnsx, naabu, httpx, katana) and the baked
  nuclei-templates, and nothing else: no Python, no git, no apt/dpkg, no
  shell. amd64: 216.8 MB compressed / 679 MB unpacked before, 145 MB / 460 MB
  after; HIGH/CRITICAL advisories in OS packages 59 to 0.
- Same runtime user (uid/gid 999, now given numerically so Kubernetes
  `runAsNonRoot` can verify it), paths, environment, entrypoint and command:
  an existing data volume stays readable.
- Debugging: there is no shell to `docker exec` into; use `docker debug` or
  `kubectl debug --target=<container>` (an ephemeral container), or run the
  image's own binaries with `--entrypoint`.
- Building the default image no longer installs the CI tools (semgrep,
  betterleaks, trivy) only to discard them: nuclei and the recon tools have
  their own stage, and the full image adds them to the CI tools.
