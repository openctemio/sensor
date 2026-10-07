### Fixed: a retest during a template install no longer reads "not installed"

- A nuclei retest or validation that started while the sensor was still
  installing its first nuclei-templates release looked its template up in an
  empty set and ended inconclusive with "not installed". The lookup now waits
  for that install, bounded by the command's own deadline, and uses the
  release it installed. Lookups during a later refresh keep the release they
  took: the swap is atomic and a held release is never removed.
- A template lookup that failed (`nuclei -tl` timing out or exiting non-zero,
  for example while the sensor validates a new release) now says the lookup
  failed instead of "not installed". The outcome is still inconclusive.
