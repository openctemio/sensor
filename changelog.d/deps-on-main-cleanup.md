### Fixed: deps-on-main check no longer fails on its own cleanup

- The CI check clones with background gc, maintenance and commit-graph writes off, and its cleanup retries and never changes the check exit status.
