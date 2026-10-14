### Documentation: README and reference match v0.21

- The README quick start pins v0.21.1, adds `--dns-search .` and explains `SENSOR_SANDBOX_NETWORK=required`; the license line says GPL-3.0, as the `LICENSE` file does.
- `docs/REFERENCE.md`: the run, Compose and cosign examples pin a release; the Compose example runs with the seccomp profile and `dns_search: .`; protocol v3 is the default transport; the tool options live on the sensor's **Tool settings** tab; the sensor pages are under Discovery > Sensors; `tools.allow` replaces `SENSOR_TOOLS` in the betterleaks notes.
