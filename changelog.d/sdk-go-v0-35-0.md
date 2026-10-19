### Security: sdk-go v0.35.0, signed jobs required for new pairings

- A newly paired sensor always requires signed jobs. With no job-signing key or root pinned it does not start until `SENSOR_JOB_SIGNING_ROOT` (from the console's install snippet) or `SENSOR_JOB_SIGNING_KEYS` is set; `SENSOR_REQUIRE_SIGNED_JOBS=false` is refused on a sensor that pinned keys, and a plain-http platform URL to a non-loopback host is an error. Existing identities are unchanged.
- A full outbox refuses new results instead of evicting queued ones. `SENSOR_OUTBOX_MAX_AGE` now deletes dead letters only; a pending result is kept until the platform acknowledges or refuses it.
- The shared isolation profile and the address deny list now follow the platform's (`ctis/addrscope`); see the sdk-go v0.35.0 changelog for the ranges newly refused.
