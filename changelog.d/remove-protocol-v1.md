### Removed: sensor protocol v1

- The sensor speaks protocol v2 only (sdk-go without the v1 fallback client).
  Against a platform that does not serve protocol v2 every call fails with
  "the platform does not serve sensor protocol v2" instead of falling back to
  the retired `/api/v1/agent/*` routes.

### Upgrade notes

- Run an OpenCTEM API that serves sensor protocol v2 (every API since
  2026-10-02; the API removed protocol v1). Upgrade the API first if it is
  older.
- `SENSOR_PROTOCOL=v1`, `-protocol v1` and `server.protocol: v1` are refused at
  start-up: remove the setting (`auto` and `v2` are the same).
