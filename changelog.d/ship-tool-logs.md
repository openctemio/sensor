### Fixed: tool and validation lines reach the command's log on the platform

- Every scanner ran on the sensor's own tool host, which had no log sink, so no tool line ever reached the platform: tasks showed an empty log.
- The host now ships through the SDK's command log (`kit.ToolLogSink`):
  - each tool's lines;
  - "Tool <name> <version> started";
  - "Tool <name> finished: <status>", with the exit code, records, duration and error class.

  This covers scans, retests and re-verifications. Lines are redacted (credentials in headers, secret-named parameters, URL user info), bounded per command and batched.
- Validate jobs write "Validation started" and "Validation finished: <outcome>" to the command's log.
- Together with the SDK's own received, admission, refusal and outcome lines, every command now has a readable log.
