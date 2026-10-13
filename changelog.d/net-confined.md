### Added: a confined sensor advertises `net.confined@1`

- When tools run out of process in a sandbox that confines their network to each task's forwarder (the container runs with `docker/seccomp/sensor.json`), the sensor advertises `net.confined@1`. A platform that knows the capability sends jobs that need confinement (a nuclei job with a web scope) only to such a sensor, so they wait for one instead of failing with "nuclei keeps to a web scope only in a tool sandbox that confines its network".
- The setup checklist reports `runtime.sandbox_network` with the detected cause and fix when tools are not confined (sdk-go).
