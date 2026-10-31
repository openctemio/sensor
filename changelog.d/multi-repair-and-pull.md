### Fixed: the multi-sensor kit pairs again with a new code

- `./sensors.sh pair NAME --pairing-code XXXX-XXXX` writes the new code into
  `sensors/NAME/sensor.env` and recreates the container, for a sensor whose
  code expired or that was stopped before anyone approved it (the sensor keeps
  its key; the platform lets a key that was never approved start again).
- `pair` pulls a missing image with progress before it starts the sensor, and
  stops with a hint when the pull hangs (`PULL_TIMEOUT_SECONDS`, 10 minutes):
  a pull interrupted with Ctrl-C can leave a stale download behind until the
  container runtime restarts.
- Ctrl-C while `pair` waits says the sensor keeps running, to approve it in the
  console and run `pair` again to watch. A refused key (approved once before) or
  a key held by another request is explained with the command to run.
- `add --api-url` drops trailing slashes.
