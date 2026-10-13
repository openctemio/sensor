### Behaviour change: dnsx filters wildcard DNS by default

- dnsx now runs with `-auto-wildcard` unless a scan sets `wildcard_filter: false`. A name that resolves only through a wildcard record of its zone is no longer reported, so a wildcard zone cannot flood the inventory with names that would then be scanned actively (api RFC-088).
- Expect a few extra DNS queries per zone (dnsx resolves random labels to detect the wildcard).
