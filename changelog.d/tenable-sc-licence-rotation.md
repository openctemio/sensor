### Added: licence guard and opt-in rotation-repository recycling for Tenable.sc coverage

- A `connector_scan` may carry `licence_guard {new_addresses, headroom}`: the sensor launches only when Tenable.sc has that free licence capacity (read from `/rest/status` at launch), and otherwise fails with `LICENCE_CAPACITY` before creating anything. After the import it reports the licence count again (`active_ips`, `active_ips_before`).
- New operation `recycle` with a `recycle` block (rotation repository name with the `openctem-` prefix, administrator key files): a batch with `rotation_repository` scans into that repository, and with `recycle_repository` deletes and recreates it first, which frees its licence count at once. Off unless the owner configures it; no other repository is ever touched. The repository fields sent on create are not yet verified against a real Tenable.sc.
- The Tenable.sc mock serves repository creation and can require administrator keys for repository changes.
