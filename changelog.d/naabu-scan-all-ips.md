### Fixed: a port scan of a host name scans every address the name resolves to

- naabu scanned only the first address of a host name, so a name behind several A/AAAA records (round robin, a load balancer, dual stack) looked closed when that one address filtered the ports. The sensor now runs naabu with `-scan-all-ips`. IPv4 and IPv6 are both scanned (naabu's default), and CDN addresses are not limited to ports 80 and 443.
- Scope is unchanged: the local policy already checks every address a name resolves to before admitting the job, `-exclude-hosts` applies to each address, and a confined task's forwarder dials only the admitted addresses.
