### Security: new pairings fail closed without a local policy and pin the platform's TLS identity

- The sensor is built with an sdk-go that brings these changes:
  - **No policy, no network jobs (new pairings).** A sensor paired by this release refuses jobs with network targets, custom templates or out-of-band callbacks until a local policy is installed (refusal `no_local_policy`). `SENSOR_REQUIRE_LOCAL_POLICY` overrides this.
  - **Built-in deny list without a policy.** Without a policy, the built-in deny list (loopback, link-local and metadata, private ranges unless allowed) now applies on every target check.
  - **Platform TLS pin.** Pairing pins the platform's TLS identity. Platform requests then refuse any other certificate authority, with no fallback to the trust store. The v3 gRPC certificate authority is kept and replaced only over a pinned channel, and a certificate failure is never answered by falling back to another transport.
  - **Posture reporting.** The sensor reports its posture: local policy required, platform pin, sandbox and network confinement. The platform flags unhardened sensors from it.
  - **SSRF guard.** The guard also refuses the NAT64, 6to4 and Teredo ranges.
  - **Organization HTTP policy.** The organization's HTTP policy narrows the requests of tools.
- **Upgrade note:** sensors paired before this release keep their behavior: no policy required and no pin. To harden one, pair it again, or set `SENSOR_REQUIRE_LOCAL_POLICY=true` and `SENSOR_CA_FINGERPRINT`. A sensor that already holds a gRPC certificate authority refuses a different one sent over HTTPS; pair it again after a deliberate change of the platform's sensor CA.
