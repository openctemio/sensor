### Upgrade notes: one data volume at /var/lib/openctem

- The install templates now mount ONE volume at `/var/lib/openctem`,
  holding `state/` (identity), `outbox/` (undelivered results) and
  `content/` (the scanner cache): one volume, one backup target. A sensor
  with a volume on each of the three directories keeps working unchanged;
  README "Data volume" has the steps to move to one volume and the backup
  command.
- The images no longer declare `VOLUME` on `/var/lib/openctem/outbox` and
  `/var/lib/openctem/content`: those anonymous volumes would shadow the
  subdirectories of a volume mounted at `/var/lib/openctem`. A container run
  with no volume for the outbox no longer gets an anonymous one: mount the
  data volume (the sensor warns at start when the state or outbox is not on
  a volume).
- `SENSOR_STATE_DIR`, `SENSOR_OUTBOX_DIR` and `SENSOR_CONTENT_DIR` stay as an
  advanced override (e.g. the content cache on other storage).
