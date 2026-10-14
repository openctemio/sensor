### Behaviour change: the OpenCTEM rules pack is the default semgrep-rules content

- Without a local rules path or registry rulesets, the sensor installs the signed OpenCTEM rules pack (`github.com/openctemio/sast-rules`) as its `semgrep-rules` content. It takes the newest release, a policy pin, or `SENSOR_CONTENT_SAST_RULES_VERSION`. opengrep and semgrep scans run it.
- A release is installed only when its cosign keyless signature (`.sigstore.json`) verifies offline (sdk-go `blobsig`) for the archive's SHA-256 and for the pack's release workflow at that tag. The content checks report `sha256, sigstore`.
- `SENSOR_CONTENT_SAST_RULES_URL` points at a mirror of the release downloads. The signature is still checked, so a mirror cannot change the rules.
- Every content source is now always managed. The "unmanaged" state (semgrep fetching `--config auto` per scan when no ruleset was chosen) and the `Unmanaged` source interface are removed.

### Upgrade notes

- Sensors with semgrep and no rules configuration now run the pack instead of `--config auto`. Set `SENSOR_CONTENT_SEMGREP_RULESETS` to keep registry rules, under the registry's licence.
- The sensor needs HTTPS to `api.github.com`, `github.com` and `release-assets.githubusercontent.com` (already allowed for the nuclei templates), or a mirror.
