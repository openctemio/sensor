### Security: naabu skips the job's excluded hosts

- The scope exclusions a scan job carries (sdk-go `ScanOptions.ExcludeHosts`, from the signed payload) reach naabu as `-exclude-hosts`, ranges written as prefixes. The SDK already cuts the job's ranges around them address by address; naabu now skips them too (api RFC-088).
- An exclusion naabu cannot read refuses the run instead of being dropped.
- sdk-go is bumped to the release with job exclusions.
