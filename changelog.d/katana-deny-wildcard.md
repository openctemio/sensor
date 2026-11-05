### Security: katana keeps away from path exclusions with a `*` segment

- A deny path with a `*` segment (`/tenants/*/admin`) became a katana out-of-scope regex that matched `*` literally, so the crawl requested `/tenants/acme/admin`. The segment now matches any one segment. The web scope filter of katana's results and the egress forwarder hold the same rule.
