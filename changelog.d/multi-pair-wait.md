### Added: `sensors.sh pair` follows one sensor until it is paired

- `deploy/multi/sensors.sh pair NAME` starts one sensor of a multi-sensor host, shows only its code, fingerprint and key while it waits for an administrator to approve it, clears the spent `SENSOR_PAIRING_CODE` from its env file once it is paired, and gives up after 15 minutes (`PAIR_WAIT_SECONDS`). `add` now points to it.
