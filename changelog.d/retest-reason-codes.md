### Fixed: a retest that cannot run a check says which of three reasons applies

- An item whose check is not in the sensor's template set now ends with the code `template_not_found`, one the sensor's safety policy never runs (templates tagged dos, fuzz, intrusive, brute-force, default-login) with `excluded_by_policy`, and one on a target the sensor could not connect to or that its network confinement refused with `target_unreachable` or `egress_refused`. The platform maps the codes to text and a suggested action; the free-text detail stays for people.
- A retest runs exactly the template id the finding was recorded with: no severity, tag or type filter applies (an info-severity template runs). A test pins this.
