### Added: `sensors.sh add` installs, starts and pairs a sensor in one command

- `./sensors.sh add NAME --api-url URL` writes the sensor, starts only it and shows its code, the link to approve it on and its fingerprint; it ends by itself once the sensor is paired and clears a spent code. `--ca-file FILE` installs the platform's private certificate authority; `--pairing-code` keeps the code-first path for automation; `--no-start` only writes the sensor.
- New `stop NAME`, `start NAME` and `down` (removes the containers, never the volumes). `status` prints one plain line per sensor: "running and paired", "waiting for approval: open <link>", or why not (an untrusted certificate authority, a refusal).
- `pair` shows the new link, refusal and untrusted-certificate lines and stops with the fix for an untrusted certificate authority.

### Behaviour change: the multi-sensor kit no longer requires a local policy

- The kit's `compose.yaml` no longer sets `SENSOR_LOCAL_POLICY` for every sensor: a sensor follows its organization's scope. A host owner narrows one sensor by writing `sensors/NAME/policy/sensor-policy.yaml` and uncommenting `SENSOR_LOCAL_POLICY` in its `sensor.env`; the `STOP` kill switch is unchanged.
- **Upgrade note:** a directory set up with an older kit keeps requiring a policy file for every sensor (`add` writes one that allows nothing there and says so). README "The local policy is optional" moves it per sensor.
