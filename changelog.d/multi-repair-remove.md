### Added: `sensors.sh repair` and `sensors.sh remove` in the multi-sensor kit

- `./sensors.sh repair NAME --pairing-code XXXX-XXXX` answers the console's
  Re-pair for one sensor: it stops the sensor, deletes only its identity
  directory on the data volume (the outbox and caches stay, since a re-pair
  keeps the sensor id), writes the code and pairs it again. It states that the
  current key keeps working until the re-pair is approved, and asks for
  confirmation unless `--yes` is given.
- `./sensors.sh remove NAME [--purge] [--yes]` stops and removes one sensor,
  its `sensors/NAME/` directory and its `compose.yaml` blocks. `--purge` also
  deletes its data volume, which loses the key and any results not yet
  delivered. Revoke or delete the sensor in the console too.
