### Fixed: a tool run is watched and the platform deadline is its budget

- The sensor now watches every tool run and uses the deadline the platform sets as the job's time budget, so a stuck run ends instead of holding its slot.
- A forwarded egress connection never outlives its task.
- The release build stamps the release tag into the binary and the publish smoke test fails when the image's `-version` differs from the tag.
