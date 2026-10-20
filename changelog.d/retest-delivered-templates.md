### Added: nuclei retests run the check the platform delivers for a finding

- The sensor reports `retest-templates:nuclei`. A retest item that names a custom template delivered with the command is checked with exactly that template instead of the managed template set; other items are unchanged.
- The SDK verifies the template like a scan's custom templates (local policy `allow_custom_templates`, the signed job or the template manifest for this sensor and command, the content check) before the tool sees it. The run keeps the tag exclusions, rate ceiling, web scope and forwarder, adds `-lna` on an unconfined task and a CPU-time cap, and drops nuclei's own signature requirement for that file only.
- A delivered template that nuclei does not load, or that its tags exclude, is `unverifiable` ("the check could not be loaded"), never `fixed`. Verdicts carry the file's `sha256:` digest.
