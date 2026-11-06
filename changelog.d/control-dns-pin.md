### Documentation: reaching the platform when DNS fails

- `docs/REFERENCE.md` explains the last-known-good platform address (`SENSOR_CONTROL_DNS_MAX_STALE`, default `24h`, from sdk-go), pinning the platform host (`extra_hosts`, `--add-host`, `hostAliases`, `/etc/hosts`), the setup checks `runtime.control_dns` and `network.core_addresses`, and why DNS servers, gateways, firewalls, the platform host and the sensor host stay out of intrusive scans. `docker-compose.example.yml` has a commented `extra_hosts` pin.
