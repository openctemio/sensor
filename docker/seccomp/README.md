# Seccomp profile for the sensor container

`sensor.json` is Docker's default seccomp profile (moby/profiles `seccomp/default.json` at commit `2ceae35d351c156cb5a8efc0fdc4a08cf94569d8`) with two rules added: `clone` and `unshare` are allowed with namespace flags, and `chroot` is allowed without `CAP_SYS_CHROOT` in the container's capability set.

That rule lets the sensor give every tool task its own user, network and mount namespaces (sdk-go `executor.Config.ConfineNetwork`, api RFC-060). A confined task has only loopback, and its only way out is its forwarder: it reaches its admitted targets and nothing else, whatever the tool does. The runtime's default profile refuses those flags without `CAP_SYS_ADMIN`, and the sensor then runs tasks unconfined, with a warning (`SENSOR_SANDBOX_NETWORK=auto`) or refuses to start (`required`).

A confined sensor advertises `net.confined@1`, and the platform keeps jobs that need confinement for such a sensor: they wait in the queue rather than fail on an unconfined one. Some jobs need confinement. A job whose target is limited to some ports or paths (`scope.limits@1`) goes only to a confined sensor. nuclei takes a job with a web scope (the tenant excluded a path on the host) only when it runs confined: the forwarder then reads every request, HTTPS included, and refuses the excluded paths, because nuclei's templates request arbitrary paths. An unconfined sensor fails such a nuclei job with "nuclei keeps to a web scope only in a tool sandbox that confines its network".

The tools themselves cannot use the rule: the sensor's own per-task seccomp filter refuses namespace creation to every tool. The one exception is the browser tool (`webshot`, in the `browser` image): its task may create user, PID and network namespaces for Chromium's renderer sandbox, and Chromium then chroots its sandboxed processes inside the user namespace it owns. Docker's default profile allows `chroot` only to a container that holds `CAP_SYS_CHROOT` (the sensor drops every capability), so the second rule allows the syscall itself; the kernel still refuses it to any process without `CAP_SYS_CHROOT` in its own user namespace, so nothing else in the container gains anything. Without the rule Chromium's sandbox cannot start and the browser tool fails instead of running without it.

Every image carries the profile it was built and tested with. Write it from the image you run, so the profile always matches the release:

```bash
sudo install -d -m 0755 /etc/openctem
docker run --rm ghcr.io/openctemio/sensor:<version> seccomp-profile \
  | sudo tee /etc/openctem/sensor-seccomp.json >/dev/null
```

```bash
docker run --security-opt seccomp=/etc/openctem/sensor-seccomp.json \
  -e SENSOR_SANDBOX=required -e SENSOR_SANDBOX_NETWORK=required \
  ghcr.io/openctemio/sensor:<version>
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
- The host must allow unprivileged user namespaces, which no container profile can override: `kernel.unprivileged_userns_clone` must not be 0 (Debian and Ubuntu) and `user.max_user_namespaces` must be positive. When the sensor's setup check `runtime.sandbox_network` reports `userns_disabled_host`, the host admin sets, persistently:

  ```bash
  echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/60-openctem-userns.conf
  sudo sysctl --system
  ```

  (or a positive `user.max_user_namespaces`). Trade-off: this re-enables unprivileged user namespaces host-wide. Ubuntu enables them by default, and its AppArmor restriction (`kernel.apparmor_restrict_unprivileged_userns=1`) still limits unconfined processes. Keep that restriction at 1 and keep the container's `docker-default` AppArmor profile; never set the restriction to 0. If confinement still fails with the restriction on and `docker-default` applied, give the sensor container an AppArmor profile that grants `userns` instead of loosening the host. On a shared machine, a dedicated host or VM for the sensor is the cleanest option.
- Kubernetes: load the file as a `Localhost` seccomp profile on the nodes and set `securityContext.seccompProfile: {type: Localhost, localhostProfile: <path>}` for the sensor container.

To update the profile, regenerate it from a newer moby/profiles commit by adding the same two rules, and record the commit above.
