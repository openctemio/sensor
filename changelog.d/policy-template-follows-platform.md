### Behaviour change: the local policy is optional; the multi-sensor template no longer allows nothing

- `deploy/multi/sensors.sh add` writes a `sensor-policy.yaml` whose `targets.allow` is commented out (with examples). Without an allow list a sensor follows the platform's signed scope; list ranges or domains only to narrow it. An empty `allow: []` still allows nothing.
- `docs/LOCAL_POLICY.md` and `docs/REFERENCE.md`: `SENSOR_REQUIRE_LOCAL_POLICY` defaults to `false`; `true` fails closed without a policy file.
- Pairs with the sdk-go change that stops requiring a policy (release it first; this change does not bump sdk-go). Upgrade: a sensor paired by an earlier fail-closed release with no policy file follows the platform's signed scope once it runs the new sdk-go; set `SENSOR_REQUIRE_LOCAL_POLICY=true` to keep fail closed.
- Trade-off: without a local policy a compromised platform could sign a wide scope. Host owners who do not trust the platform install a narrowing policy or set `SENSOR_REQUIRE_LOCAL_POLICY=true`.
