### Security: katana keeps to the job's web scope

- A job can carry a web scope: hosts, path prefixes, deny paths and methods (sdk-go `pkg/webscope`). katana declares `features.web_scope` (descriptor 2.1.0) and maps the scope onto its flags:
  - each deny path becomes an out-of-scope regex (`-cos`) that matches it in any case and percent-encoded, with repeated slashes or a backslash;
  - path prefixes and hosts become an in-scope regex (`-cs`);
  - the crawl stays on the target's host (`-fs fqdn`) with redirects off;
  - form filling is off unless the scope allows POST.
- The results are filtered with the scope again before they are reported.
- A real katana crawl of a site that links to `/admin` and `/logout` (plain, dot segments, upper case, percent-encoded, a form and a script `fetch`) made no request to either. Without the scope, the same crawl requested both.
- A job with a web scope fails for a recon tool that cannot keep to one (every tool but katana), and an invalid scope fails the job. Neither runs without the scope.
