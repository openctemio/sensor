### Security: re-verify results no longer carry the credentials of the matched URL

- A nuclei re-verify (validate) result put the raw `matched-at` URL into its `MatchedAt` and its summary, which the platform shows as the retest reason. A credential in that URL, such as an `api_key` query value or user info, reached the platform. Both now use the redacted URL, as the evidence already did.
