### Added: opengrep SAST scanner and image

- New native tool `opengrep` (`sast.code@1`), detected when the `opengrep` binary answers `--version`. It runs local rules only: the managed `semgrep-rules` content (which opengrep reads unchanged), the platform's custom rules of a scan, or `SENSOR_CONTENT_SEMGREP_RULES_PATH` for a one-shot run. A registry name (`auto`, `p/...`), a URL or a missing path is refused before the run, and the tool descriptor gives it no network (`permissions.network: none`). A scan with no rules fails with an explicit error.
- Tool settings: `taint_intrafile` (opengrep `--taint-intrafile`), `rule_timeout` (`--timeout`) and `max_target_bytes` (`--max-target-bytes`) per scan. `jobs` (`--jobs`) and `max_memory_mb` (`--max-memory`) are sensor settings only.
- Results are parsed with the ctis `opengrep` format and reported under the tool name `opengrep`. opengrep's match-based id becomes the partial fingerprint `matchBasedId/v1`, and the finding fingerprint stays the one a semgrep run produced, so existing semgrep findings keep their identity.
- When opengrep is installed, the rules content is checked with opengrep (without `--metrics`, which opengrep refuses) and reported under opengrep. Without a managed bundle it reports "none (opengrep runs local rules only)".
- New image variant `-opengrep` (`Dockerfile.opengrep`). It installs the opengrep release binary pinned by version and SHA-256 per architecture, verifies the binary's keyless cosign signature against the opengrep release workflow identity, and unpacks the binary's runtime at build time so the image runs it read-only. The image smoke test runs a local-rules scan on a read-only image with no network.

### Upgrade notes

- Additive: semgrep and its image are unchanged.
