### Added: sensor profile images passive, standard and full

- New images `ghcr.io/openctemio/sensor:<version>-passive` (passive discovery only: subfinder, with rdap and asn compiled in) and `:<version>-full` (every tool), and the tag `:<version>-standard` for the default image. All are multi-arch, signed, with SBOM and provenance, run as uid 999 and name their profile in the label `io.openctem.sensor.profile`. See docs/PROFILES.md.
- The passive image holds no program that can touch a target: the release smoke test derives the programs of every tool above T0 from the compiled-in manifests and fails the build if one is in the image, and checks that every tool the daemon detects is T0. dnsx is not in it because dnsx-enum (T1) runs the same binary.
- Nothing changes for existing images and tags.
