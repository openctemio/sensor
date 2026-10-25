### Documentation: current install snippet and a pairing troubleshooting section

- The README quick start pins one `SENSOR_VERSION` (now v0.25.0) for both the image and the seccomp profile, includes `SENSOR_PAIRING_CODE`, and has a "Troubleshooting pairing" table: clock skew (the 2-minute signature tolerance, `chronyc makestep`, `makestep 1 -1`), the per-address 429, a spent enrollment token, a code nobody approved.
- Release Prepare now rewrites the install pins in README.md and docs/REFERENCE.md to the release being prepared, so the snippet no longer points at an old tag.
