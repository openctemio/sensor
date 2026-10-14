### Security: inline ignore comments and .semgrepignore no longer hide SAST results

- opengrep and semgrep run with `--disable-nosem` and `--x-ignore-semgrepignore-files`: a comment or ignore file in the scanned repository is the author's claim, not a decision. The results are reported and the platform decides (known false positives, approved exceptions).
- The paths a default ignore file skipped (dependencies, build output, tests) are excluded by the sensor (`DefaultExcludes`).
