### Security: sdk-go v0.47.2

- The egress forwarder bounds every response head it reads (64 KiB, one idle window), so a hostile target can no longer exhaust the sensor's memory with an endless or dripping header. It bounds the upstream TLS handshake the same way.
- Web scope deny paths hold when stored escaped (`/files/My%20Docs`), with `*` segments (`/tenants/*/admin`), and for lenient server spellings (case folding to ASCII, trailing dots, double decoding). This uses contract webpath v1.3.1.
