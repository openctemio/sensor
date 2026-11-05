### Security: nuclei never runs templates that only harvest personal data

- Every nuclei run passes `-exclude-id email-extractor,secrets-patterns-pii,rdap-whois,credit-card-number-detect`. These templates report no weakness: their result is the e-mail addresses, phone numbers, registrant contact details or card numbers of the target, which then landed in findings. A scan cannot re-admit them; an operator's or a scan's own excluded ids are added to the list.
