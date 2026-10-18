### Changed: bundled tool versions

- trivy 0.76.0 (was 0.75.0), opengrep 1.31.0 (was 1.30.2), subfinder 2.17.0 (was 2.16.0), katana 1.8.0 (was 1.7.0). Each archive is pinned by its sha256 from the release's checksums; the opengrep binary's signing certificate names its release workflow at `release-v1.31.0`, and the image build still verifies the signature with cosign.
- The flag checks run against the new `-h` output of subfinder and katana: no flag the sensor passes was removed.
