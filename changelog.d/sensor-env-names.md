### Upgrade notes: every sensor setting is SENSOR_-prefixed; old names stop the sensor

- `API_URL` → `SENSOR_API_URL`, `API_KEY` → `SENSOR_API_KEY`, `REGION` → `SENSOR_REGION`, `PLATFORM_KEY_AUTORENEW` → `SENSOR_KEY_AUTORENEW`.
- `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` are no longer read as aliases; `OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS` is gone. `SENSOR_ALLOW_PRIVATE_TARGETS` is the one switch for private scan targets (the SDK egress switch no longer widens targets).
- The sensor refuses to start (exit 2) while a removed name is set and names its replacement. **Rename them in your `.env`, compose file, systemd unit or Helm values before upgrading.** Install snippets from a platform that advertises this release use the new names.
