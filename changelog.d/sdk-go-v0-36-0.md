### Added: encrypted local store, job journal and janitor (sdk-go v0.36.0)

- New settings `SENSOR_STORE_DIR`, `SENSOR_STORE_KEY_FILE` and `SENSOR_WORKSPACE_DIR` (defaults `store/` and `workspaces/` next to the outbox). New outbox items are sealed per organization; at start the sensor reports jobs a crash left unfinished as failed, sweeps their workspaces and runs a janitor. The sensor stops claiming work while the outbox is full or storage is low.
- The images create `store/` and `workspaces/` (0700, owned by the sensor user) under `/var/lib/openctem`. Keep them on the same data volume as `outbox/`; mount `SENSOR_STORE_KEY_FILE` as a separate secret to keep the key off the volume. No key is ever built into an image.
- Upgrade: the existing `outbox.key` is adopted, nothing is re-encrypted. Rolling back to an older sensor once sealed items exist refuses to start with `ErrStoreRequired` instead of losing them.
