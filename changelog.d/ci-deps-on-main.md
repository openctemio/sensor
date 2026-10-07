### Changed: CI refuses openctemio dependencies pinned off main

- A new CI job fails when `go.mod` pins sdk-go or ctis to a commit that is not
  on that repository's `main` branch. A feature-branch pin breaks once the
  branch is squash-merged (the commit then exists on no branch), and a release
  built from it cannot be reproduced.

- Re-pins sdk-go from `3e8d221` (a branch commit of sdk-go #192, squashed on
  main as `3883b87`) to `3883b87`: the same change, now on main.
