### Fixed: a re-pair keeps the sensor's name; `-help` lists the subcommands

- `pair -repair` without `-name` or `SENSOR_NAME` now proposes the sensor's current name. Before, it proposed the host name, so an approval that left the name unchanged renamed the sensor. A name given with `-name` or `SENSOR_NAME` still wins.
- `-help` now lists the `pair`, `policy` and `tools` subcommands before the flags.
