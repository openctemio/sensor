### Security: katana never requests a logout, delete or reset link

- Every crawl gets an out-of-scope regex (`-cos`) built from the contract's destructive verbs (any case, any letter percent-encoded), and its results are filtered with contract `webpath.Destructive`. The deep crawler preset no longer fills forms.

### Added: path discovery (`webguess`, `enumerate.web_paths@1`)

- A compiled-in tool that requests the candidate paths the platform puts in the signed job (the `paths` wordlist slot: the inline list derived from the organization's inventory) and reports the ones the calibrated differ (sdk-go `pkg/webdiff`) confirms, as CTIS endpoints with status, content type, auth state and `extensions["io.openctem"].response` `{size, hash}`; never a body.
- It refuses to run unless the job's web scope allows only GET and HEAD and caps the requests per host; it filters candidates with the scope, `exclude_paths` and the destructive check (`scope_filtered`), never adds a path and never recurses. An edge-challenged origin is skipped.
- Each origin not fully covered is a coverage gap of the run (`coverage_gaps`: host = origin, reason = main reason, detail = `reason=count ...`); an edge stop or a rate limit also marks the target.

### Changed

- sdk-go and contract pinned to the commits that add `pkg/webdiff`, the web-scope request cap and contract `webpath` (until their releases).

### Added: the backup file check

- `openctem-backup-file-signature`, a nuclei template compiled into the sensor, that the platform can request by id: one GET of a guessed backup, archive or dump URL, a match only for a non-HTML 200 whose first bytes are a zip, gzip or tar signature or a MySQL, MariaDB or PostgreSQL dump header. It runs from a copy the sensor signs for that run (the platform needs no template delivery), with `-disable-unsigned-templates` kept on.

### Added: the nuclei setting `template_ids`

- A scan's `template_ids` (`scanner_config.template_ids`) selects the sensor's own compiled-in checks: only their ids are accepted (any other id fails the scan), the run loads only their run-signed copies with `-id`, signatures stay required and the tier's `-etags` stay on. The platform's verification of a guessed backup, archive or dump file uses it with `openctem-backup-file-signature`.
