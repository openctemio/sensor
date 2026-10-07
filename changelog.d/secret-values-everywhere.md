### Security: a secret scanner's raw match no longer survives in the title or other fields

- The betterleaks and trivy parsers mask the raw secret, the match line and each secret-looking word of the match in every field of a secret finding. This covers the title, message, description, the `commit_message` property, tags and fingerprints, not only the snippet. Before, a rule description or a commit message that repeated the secret carried it to the platform.
- sdk-go is re-pinned: the tool runtime's output checks apply the same rule to every out-of-process tool, and the importers mask secrets in every field.
