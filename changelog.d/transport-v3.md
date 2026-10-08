### Added: sensor protocol v3 (gRPC over mutual TLS, HTTPS fallback)

- A paired sensor speaks protocol v3 when the platform serves it (openctem api RFC-059, sdk-go `client.EnableTransportV3`): gRPC over mutual TLS with a 7-day client certificate for its own key, pinned to the platform's sensor CA; HTTPS with signed requests where gRPC is blocked (the reason is shown on the platform's Sensors page); protocol v2 against a platform without v3. Jobs are pushed over the control stream instead of waiting for the next heartbeat.
- `SENSOR_TRANSPORT=auto|grpc|https|v2` (default `auto`). Bearer-key sensors stay on v2.
- The identity directory (signing key, certificate, pinned CA) is a protected path of the tool sandbox.
