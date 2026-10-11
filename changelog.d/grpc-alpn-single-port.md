### Added: protocol v3 gRPC on the platform's own port (no extra port)

- The gRPC binding offers the ALPN id `openctem-sensor/3` (sdk-go `client.SensorALPN`). A platform whose gateway routes that id (openctem api RFC-059 T16) serves gRPC with mutual TLS on the same port 443 as the web UI, also when it is reached by an IP address or a single host name. Nothing to configure on the sensor: it uses the `grpc_alpn_endpoint` the platform's hello names, and keeps the HTTPS binding where the platform offers none.

### Fixed: a platform restart no longer drops the sensor from protocol v3 to v2

- sdk-go keeps a working v3 binding when the platform does not answer a
  negotiation (a restart, a gateway 502) and retries after about 30 seconds;
  a sensor with no binding yet reports `platform_unreachable`.
