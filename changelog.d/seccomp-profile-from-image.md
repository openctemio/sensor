### Added: `openctemio-sensor seccomp-profile` prints the image's own seccomp profile

- `docker run --rm ghcr.io/openctemio/sensor:<version> seccomp-profile | sudo tee /etc/openctem/sensor-seccomp.json` writes the container seccomp profile this release was built and tested with (`docker/seccomp/sensor.json`, embedded in the binary). The install commands can use it instead of downloading the profile and checking a checksum served by the same server: the profile then comes from the signed image and always matches the running release.
