### Fixed: the asn lookup no longer fails when its routing dataset source is down

- A failed refresh of the routing dataset never fails a task while any valid cached copy exists, whatever its age; the task warns with the copy's age and source. Refreshes use a conditional request (`ETag`, `Last-Modified`), and a download is kept only if it is a complete gzip file with at least 100,000 valid rows.
- With no cached copy (first run) the download is retried with back-off for about 90 seconds, then each address is looked up through RDAP at the regional registry (found through the IANA bootstrap). If that fails too the task ends with a retryable `source_unavailable` error naming the sources and statuses, instead of a tool error.
- The IANA bootstrap file of the `rdap` lookup also keeps and uses a stale cached copy at any age.

### Added: host-local mirrors for the lookup data sources

- `SENSOR_ASN_DATASET_URL` and `SENSOR_RDAP_BOOTSTRAP_URL` (https) point the lookups at a mirror on an air-gapped network; `SENSOR_ASN_RDAP_FALLBACK=off` turns the registry fallback off. They are set on the sensor host only; the platform cannot set them.
- The config report carries a `lookup.asn_dataset` check with the dataset's age, last refresh result and source.
