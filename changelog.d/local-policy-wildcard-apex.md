### Behaviour change: `*.domain` in the local policy covers the domain itself

- A `targets.allow` or `targets.deny` entry `*.example.com` now covers `example.com` and every name below it. It used to cover only the names below. This is how the platform reads a scope pattern (api RFC-054 §4.1), so the sensor and the platform agree on what `*.example.com` means.
- To keep the apex out of an allow wildcard, add `example.com` to `targets.deny`. A deny wildcard now refuses the apex too.
- Entries and targets compare case-insensitively, without a trailing dot, in IDNA ASCII form.
- Needs sdk-go with the matching change (sdk-go #192).
