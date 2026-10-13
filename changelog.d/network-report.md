### Documentation: the network report the sensor sends

- Since v0.19.0 (sdk-go v0.25.0 `pkg/netctx`, api RFC-089) the manifest carries a network report: the host owner's `SENSOR_NETWORK_SITE`, `SENSOR_NETWORK_REACH`, `SENSOR_NETWORK_DNS_SUFFIXES` and `SENSOR_INTERNET`, and the detected on-link prefixes, routes, resolvers and egress address. The platform uses it to route jobs to a sensor that can reach their targets; it never widens what the sensor is given.
- The reference now documents it, and tests prove it on the daemon's wiring: never wider than the local policy (no private prefix on a sensor that may not scan private targets), `summary` by default, `SENSOR_NETWORK_REPORT=off` honoured, an invalid value stops the sensor.
