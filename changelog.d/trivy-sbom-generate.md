### Added: trivy builds software bills of materials (`sbom.generate@1`)

- trivy now implements the `sbom.generate@1` capability (descriptor version 2.1.0). An SBOM job lists every package of a repository or image (`--list-all-pkgs`) and runs only trivy's license scanner, so no vulnerability matching happens and no vulnerability database is needed. Packages are reported as CTIS dependencies with name and version.
- The `dev_deps` param includes development dependencies.
- Other trivy capabilities run as before. The platform routes `sbom.generate@1` once its catalog marks the capability as routed.
