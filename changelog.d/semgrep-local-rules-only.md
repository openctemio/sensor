### Security: semgrep runs local rules only, never `--config auto`

- The semgrep scanner no longer defaults to `--config auto` when no managed rules bundle is installed yet, and refuses a registry name (`auto`, `p/…`, `r/…`), a URL or a flag as its rules or as a scan's `config_file`. Such a config made semgrep fetch rules from the rules registry, under that registry's licence, on a tenant's behalf. A scan without local rules now fails with "no rules to run", as opengrep's does.
- semgrep runs with `--metrics off`.
- A one-shot semgrep run reads `SENSOR_CONTENT_SEMGREP_RULES_PATH`, as opengrep's does. Registry rulesets an operator chooses still come through the content manager (`SENSOR_CONTENT_SEMGREP_RULESETS`) as a local, checked bundle.
