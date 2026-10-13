### Added: recon tools keep to the platform's per-target budget and report progress

- When a scan command carries a task budget, every httpx, naabu, dnsx,
  subfinder and katana run on one target is stopped at the per-target budget
  when that is shorter than the tool's own timeout: one host that never
  answers costs one budget, and the other targets go on. A budget never
  lengthens a configured timeout.
- Each target a recon tool settles counts toward the command's progress,
  which the heartbeat reports, so the platform can tell a slow task from a
  stuck one. Needs sdk-go with task budgets.
