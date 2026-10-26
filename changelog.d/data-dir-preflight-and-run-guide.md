### Added: the daemon checks its data directories at start and says how to fix them

- A daemon whose data directory (`/var/lib/openctem` and its `outbox`, `state`, `store`, `workspaces` and `content` directories, or the paths set by `SENSOR_*_DIR`) is not writable by the sensor's user now stops at once with one message: the path, the owner uid:gid, the sensor's own uid:gid and the two fixes (`chown -R` for a bind mount, or a named volume). Before, it died with `content: mkdir /var/lib/openctem/content: permission denied` and a restart policy looped it. A bind mount owned by another user is the usual cause.

### Documentation: a complete "Run the sensor" guide and an example Compose file

- `docs/RUN.md` covers prerequisites, pairing, `docker run` and Compose, what lives in the data directory and how to back it up, the environment variables, capabilities and seccomp, upgrade, several sensors on one host, Kubernetes, removal and troubleshooting. `docker-compose.example.yml` matches it.
- The user ids are fixed and documented: 999 in the default image, 1001 in the per-tool images, 65532 in the slim image. They are unchanged, so existing volumes keep working.
