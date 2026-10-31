### Added: several sensors on one host from one directory

- `deploy/multi/` runs any number of sensors from one Compose file: one
  service per sensor with its own env file, data volume, network and
  sensor-local policy directory, and the shared hardening (read-only root
  filesystem, no capabilities, no-new-privileges, the release's seccomp
  profile with `SENSOR_SANDBOX_NETWORK=required`, memory, CPU and process
  limits). `./sensors.sh add NAME` adds a sensor, `./sensors.sh upgrade
  vX.Y.Z` verifies the image signature and moves every sensor to the
  release. See `deploy/multi/README.md` for when to use it instead of one
  sensor or a shared sensor.

### Documentation

- The install guides listed in `scripts/install-guides.txt` (README, docs/,
  the example Compose file, deploy/multi) pin the current release: the
  release PR rewrites every pin (`scripts/install-pins.sh update`), and CI
  fails when a pin, a `SENSOR_*` setting or a flag in a guide is not the
  current one. `docs/RUN.md` and `docker-compose.example.yml` pinned
  v0.26.0 and v0.27.0; the binary download in `docs/REFERENCE.md` pinned
  0.11.0.
