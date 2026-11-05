### Added: web screenshots in the browser image (webshot)

- New tool `webshot` (capability `capture.screenshot@1`, T1) in the new image `ghcr.io/openctemio/sensor:<version>-browser`:
  headless Chromium loads each web origin of the job and the sensor reports the picture with status, title, server and
  final URL as the origin's `web_evidence` (api RFC-081). The default image is unchanged and carries no browser.
- The browser runs only in the full task sandbox (the image sets `SENSOR_SANDBOX=required` and
  `SENSOR_SANDBOX_NETWORK=required`) with Chromium's own sandbox on: GET and HEAD only, the job's targets and web scope
  only, a request budget per page, no WebSocket/WebRTC, no downloads; page time, pixel and size caps; the image is
  re-encoded before it leaves the task. Settings: `page_timeout`, `full_page`, `max_requests` (scan), `max_image_kb`
  (sensor). See docs/PROFILES.md.

### Security: the seccomp profile allows chroot

- `docker/seccomp/sensor.json` (printed by `openctemio-sensor seccomp-profile`) also allows `chroot`, which Chromium's
  sandbox uses inside a user namespace it owns. The kernel still refuses `chroot` to any process without
  `CAP_SYS_CHROOT` in its own namespace. Write the profile again from the new image when you upgrade.
