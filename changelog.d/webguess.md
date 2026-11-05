### Security: katana never requests a logout, delete or reset link

- Every crawl gets an out-of-scope regex (`-cos`) built from the contract's destructive verbs (any case, any letter percent-encoded), and its results are filtered with contract `webpath.Destructive`. The deep crawler preset no longer fills forms.

### Added: path discovery (`webguess`, `enumerate.web_paths@1`)

- A compiled-in tool that requests the candidate paths the platform puts in the signed job (the `paths` wordlist slot: the inline list derived from the organization's inventory) and reports the ones the calibrated differ (sdk-go `pkg/webdiff`) confirms, as CTIS endpoints with status, content type, auth state and `extensions["io.openctem"].response` `{size, hash}`; never a body.
- It refuses to run unless the job's web scope allows only GET and HEAD and caps the requests per host; it filters candidates with the scope, `exclude_paths` and the destructive check (`scope_filtered`), never adds a path and never recurses. An edge-challenged origin is skipped.
- Each origin not fully covered is a coverage gap of the run (`coverage_gaps`: host = origin, reason = main reason, detail = `reason=count ...`); an edge stop or a rate limit also marks the target.

### Changed

- sdk-go and contract pinned to the commits that add `pkg/webdiff`, the web-scope request cap and contract `webpath` (until their releases).
