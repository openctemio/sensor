### Security: required identification is never run in process

- A job whose `http_policy` requires identification, or carries a query parameter or a User-Agent rotation list, is handed to the tool host (which enforces it) and refused for a tool run in this process, even when it carries no value. A job that requires identification and cannot be identified is refused with the reason; no request is sent.
- The sensor advertises `http.identity.required@1` with `http.identity@1` when its tools run out of process, so the platform gives it jobs that require identification.

### Added: User-Agent rotation

- The local policy accepts `http.user_agents` (up to 200, exclusive with `http.user_agent`); each target host of a run gets one value, the same for every request of the run (sdk-go tool host). Requires sdk-go with openctemio/sdk-go#483.
