### Changed

- httpx follows redirects on the same host only (`-follow-host-redirects`).
  It used to follow any redirect, so a scanned host could point the probe
  at another host.
- katana crawls the target host only (`-fs fqdn`, was `rdn`: every host
  under the registrable domain), and URLs on any other host are dropped
  from its results.
