# Seccomp profile for the sensor container

`sensor.json` is Docker's default seccomp profile (moby/profiles `seccomp/default.json` at commit `2ceae35d351c156cb5a8efc0fdc4a08cf94569d8`) with one rule added: `clone` and `unshare` are allowed with namespace flags.

That rule lets the sensor give every tool task its own user, network and mount namespaces (sdk-go `executor.Config.ConfineNetwork`, api RFC-060). A confined task has only loopback, and its only way out is its forwarder: it reaches its admitted targets and nothing else, whatever the tool does. The runtime's default profile refuses those flags without `CAP_SYS_ADMIN`, and the sensor then runs tasks unconfined, with a warning (`SENSOR_SANDBOX_NETWORK=auto`) or refuses to start (`required`).

A confined sensor advertises `net.confined@1`, and the platform keeps jobs that need confinement for such a sensor: they wait in the queue rather than fail on an unconfined one. Some jobs need confinement. A job whose target is limited to some ports or paths (`scope.limits@1`) goes only to a confined sensor. nuclei takes a job with a web scope (the tenant excluded a path on the host) only when it runs confined: the forwarder then reads every request, HTTPS included, and refuses the excluded paths, because nuclei's templates request arbitrary paths. An unconfined sensor fails such a nuclei job with "nuclei keeps to a web scope only in a tool sandbox that confines its network".

The tools themselves cannot use the rule: the sensor's own per-task seccomp filter refuses namespace creation to every tool.

```bash
docker run --security-opt seccomp=docker/seccomp/sensor.json \
  -e SENSOR_SANDBOX=required -e SENSOR_SANDBOX_NETWORK=required \
  ghcr.io/openctemio/sensor:<version> -daemon
```

Compose:

```yaml
services:
  sensor:
    image: ghcr.io/openctemio/sensor:<version>
    security_opt:
      - seccomp=./sensor.json
    environment:
      SENSOR_SANDBOX: required
      SENSOR_SANDBOX_NETWORK: required
```

Notes:
- Run the container as its non-root user (the image default). The sensor maps only its own user into each task's namespace.
- Keep Docker's default AppArmor profile. On an Ubuntu host the AppArmor restriction on unprivileged user namespaces applies to unconfined processes, so `apparmor=unconfined` stops confinement working.
- Kubernetes: load the file as a `Localhost` seccomp profile on the nodes and set `securityContext.seccompProfile: {type: Localhost, localhostProfile: <path>}` for the sensor container.

To update the profile, regenerate it from a newer moby/profiles commit by adding the same rule, and record the commit above.
