### Security: a bug-bounty program's identification reaches every request

- nuclei (scans, re-verification and retests), httpx and katana send the job's identification on every request: the organization's User-Agent and headers, such as the header a bug-bounty program requires of its researchers (`-header` / `-H`). A configured header of the same name is replaced. Before, these tools never received the headers, so a program's targets could be probed without them.
- Their descriptors declare `features.http_identity`. The SDK runtime refuses identification-carrying tasks for any HTTP tool that does not (sdk-go: enforced per task). Port scans, host discovery, DNS and tools that reach no target are not affected.
- The sensor advertises `http.identity@1` when its tools run through the tool host. The platform gives jobs that carry an identification only to sensors that report it.
