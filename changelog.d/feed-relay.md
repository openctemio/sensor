### Added: a platform sensor can relay the platform's signed feeds

- `SENSOR_FEED_RELAY=1` on a shared (platform) sensor with internet access makes it relay the platform's signed feeds (vulnerability feed with KEV/EPSS, release feed), so a platform with no outbound access still gets them (api RFC-142). It downloads only from the official feed origins and `SENSOR_FEED_RELAY_ORIGINS`, through the SSRF-guarded client; the platform verifies every file with each feed's pinned root. Off by default; a usage error on any other sensor.
