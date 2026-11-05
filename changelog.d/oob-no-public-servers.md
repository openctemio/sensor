### Security: nuclei never uses the public interaction servers for out-of-band callbacks

- A scan whose job asked for callbacks (`allow_interactsh`) and that ran on a sensor without its own server used nuclei's public `oast.*` servers, which saw every target name and request that called back. Callbacks now run only with the server this sensor's operator configures (`SENSOR_OOB_SERVER`); without one the scan runs with `-ni`. The scanner-level "default servers" switch is removed.
- On a sensor that confines its tools, nuclei runs with `-iserver http://<server> -pi`: the task's forwarder carries only the interaction API to that server over verified TLS and adds the token (`SENSOR_OOB_TOKEN`) itself. The token is no longer a nuclei credential and never appears in nuclei's arguments, environment or task configuration. A sensor that does not confine its tools reaches a server without a token directly over https, and runs without callbacks when the server needs a token.
- The image's nuclei is built with interactsh v1.4.1, whose correlation ids no longer carry a hash of the sensor's host name.

### Behaviour change: callbacks that cannot be used narrow the scan instead of failing it

- A job that asks for callbacks on a sensor that cannot use them runs without them and its result carries `oob: {"state": "unavailable", "reason": ...}` (`no_server`, `local_policy`, `requires_confined_sensor`, `disabled_on_sensor`, `registration_failed`); a scan that used them carries `oob: {"state": "on"}`. A local policy's `allow_interactsh: false` no longer refuses the job, and a policy without the key follows the platform (sdk-go).
- nuclei runs that use callbacks keep late hits: `-interactions-eviction 900 -interactions-cooldown-period 60 -interactions-cache-size 50000 -interactions-poll-duration 5` (nuclei's defaults dropped callbacks that arrived more than a minute after their request). Such a run takes up to a minute longer.

### Added: interaction server settings

- `SENSOR_OOB_SERVER`, `SENSOR_OOB_TOKEN`, `SENSOR_OOB_ALLOW_PRIVATE`, `SENSOR_OOB_CA_FILE` (see REFERENCE.md, "Out-of-band callbacks"). An invalid value stops the sensor at start.
