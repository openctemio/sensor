### Security: built-in tools work under network confinement; a seccomp profile that allows it

- Where the sandbox confines a task's network (sdk-go `executor.Config.ConfineNetwork`, api RFC-060), the task's only way out is its forwarder, and the built-in wrappers point their tools at the relay (`OPENCTEM_EGRESS_PROXY`):
  - nuclei, httpx, katana and subfinder through `-proxy`;
  - naabu runs its connect scan through the relay's SOCKS5;
  - dnsx and naabu use the relay as their resolver, since a confined task reaches no other.

  Outside confinement nothing changes.
- One-shot runs read `SENSOR_SANDBOX_NETWORK=auto|required|off` (default `auto`) next to `SENSOR_SANDBOX`, as a daemon does.
- `docker/seccomp/sensor.json`: Docker's default seccomp profile plus `clone`/`unshare` with namespace flags, which confinement needs. See `docker/seccomp/README.md` for `docker run`, Compose and Kubernetes. The tools themselves still cannot create namespaces (the sensor's per-task filter refuses it).
- sdk-go pinned to its `main` commit `9f08dc1` (network confinement in the executor and the tool host, sdk-go#212 and #213).
