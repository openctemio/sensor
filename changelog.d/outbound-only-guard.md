### Security: the outbound-only rule is enforced by tests; the webhook collector is removed

- A sensor never accepts inbound connections: all control flows over the connection it opens to the platform (api RFC-040 §11.1). New tests fail the build when the sensor binary:
  - links a package that serves over HTTP (`net/http/pprof`, `promhttp`);
  - calls a network listener outside a reviewed allow list (the per-task relays on loopback inside a private network namespace, and the egress forwarder Unix socket).
- The image smoke test fails when an image exposes a port.
- The `webhook` collector is removed. It could listen on `:8080` without a secret, although nothing started it. A configuration that names it now fails with "collector \"webhook\" was removed: sensors accept no inbound connections".
