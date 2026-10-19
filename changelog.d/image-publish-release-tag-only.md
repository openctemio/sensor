### Security: the image workflow publishes only from a release tag

- `docker-publish.yml` refuses to run unless it runs on a `refs/tags/v*` tag, and a manual run must name that same tag as its version. A run from a branch can no longer publish or overwrite a release image.
- An existing version tag (`vX.Y.Z`, `vX.Y.Z-<variant>`) is never moved to a different image; the run fails unless the tag already points at the same digest.
- The index is pushed under a per-commit tag, signed and verified by digest against the exact identity `docker-publish.yml@refs/tags/<version>`, and only then do the version and `latest` tags move (and their digests are checked).
- The release workflow's GitHub release assets use `mode: keep-existing`, so a re-run does not replace assets under an existing tag.
