### Added: nuclei re-verification reports every request it made

- A retest or re-verification of a nuclei finding now reports one line per request of the template (URL without query values, status, whether it matched, a CDN or WAF marker, a failure class), not only the exchange kept as evidence. A template that probes several paths (for example swagger) lets the platform judge the finding's own endpoint. Older platforms ignore the lines.
