### Fixed: a confined port scan finds open ports again

- With the network confinement on (`SENSOR_SANDBOX_NETWORK=auto` or `required`), naabu resolved its target names and dialed the addresses over the task forwarder's SOCKS5, and every connection was refused (`IP is not a target`), so the scan reported "ok" with no ports. The forwarder now admits the addresses a target name was pinned to at admission (sdk-go). Each address is admitted alone, with the name's ports and scope limits.
- A target that the confinement kept a tool from reaching is now reported `failed` with class `egress_refused`, not `done`. The task is partial, and its log says how many targets were not reached.

### Upgrade notes

- Update the platform first (it must accept the ctis `egress_refused` class). An older platform hands such a target out again as unfinished.
